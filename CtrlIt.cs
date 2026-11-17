// CtrlIt - rest the mouse on an IP address in any window to get
// Ping / Traceroute / Reverse lookup buttons.
//
// Build: double-click build.bat (uses the C# compiler that ships with Windows).
// Written in C# 5 so the built-in .NET Framework 4.x compiler accepts it.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Automation.Text;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: System.Reflection.AssemblyTitle(CtrlIt.AppInfo.Name)]
[assembly: System.Reflection.AssemblyProduct(CtrlIt.AppInfo.Name)]
[assembly: System.Reflection.AssemblyDescription("Point at an IP address or hostname anywhere in Windows to ping, connect or diagnose it")]
[assembly: System.Reflection.AssemblyCopyright("Copyright (c) 2026 " + CtrlIt.AppInfo.Author + " - MIT licence")]
[assembly: System.Reflection.AssemblyVersion(CtrlIt.AppInfo.Version + ".0")]
[assembly: System.Reflection.AssemblyFileVersion(CtrlIt.AppInfo.Version + ".0")]

namespace CtrlIt
{
    // ---------------------------------------------------------------- native

    static class Native
    {
        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(int vKey);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll")]
        public static extern bool UnregisterHotKey(IntPtr hWnd, int id);

        [DllImport("user32.dll")]
        public static extern bool SetProcessDpiAwarenessContext(IntPtr value);

        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        [DllImport("user32.dll")]
        public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter,
            int x, int y, int cx, int cy, uint flags);

        public const int VK_LBUTTON = 0x01;
        public const int VK_RBUTTON = 0x02;
        public const int VK_MBUTTON = 0x04;
        public const int VK_CONTROL = 0x11;

        public static bool IsDown(int vk)
        {
            return (GetAsyncKeyState(vk) & 0x8000) != 0;
        }

        // Physical pixel coordinates everywhere, so the mouse position matches
        // what UI Automation reports on any monitor.
        public static void EnableDpiAwareness()
        {
            try
            {
                if (SetProcessDpiAwarenessContext(new IntPtr(-4))) return; // per-monitor v2
            }
            catch (Exception) { }
            try { SetProcessDPIAware(); }
            catch (Exception) { }
        }
    }

    // -------------------------------------------------------------- settings

    static class Settings
    {
        const string KeyPath = @"Software\CtrlIt";
        const string OldKeyPath = @"Software\IPHover";   // the name before the rename
        const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunName = "CtrlIt";
        const string OldRunName = "IPHover";

        public static volatile bool Enabled = true;
        public static volatile bool RequireCtrl = false;
        public static volatile bool UseOcr = true;
        public static volatile bool HostOnCtrl = true;

        public static void Load()
        {
            try
            {
                MigrateStartup();
                RegistryKey k = Registry.CurrentUser.OpenSubKey(KeyPath);
                if (k == null) k = Registry.CurrentUser.OpenSubKey(OldKeyPath);   // keep settings from IP Hover
                using (k)
                {
                    if (k == null) return;
                    Enabled = Convert.ToInt32(k.GetValue("Enabled", 1)) != 0;
                    RequireCtrl = Convert.ToInt32(k.GetValue("RequireCtrl", 0)) != 0;
                    UseOcr = Convert.ToInt32(k.GetValue("UseOcr", 1)) != 0;
                    HostOnCtrl = Convert.ToInt32(k.GetValue("HostOnCtrl", 1)) != 0;
                }
            }
            catch (Exception) { }
        }

        public static void Save()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    k.SetValue("Enabled", Enabled ? 1 : 0, RegistryValueKind.DWord);
                    k.SetValue("RequireCtrl", RequireCtrl ? 1 : 0, RegistryValueKind.DWord);
                    k.SetValue("UseOcr", UseOcr ? 1 : 0, RegistryValueKind.DWord);
                    k.SetValue("HostOnCtrl", HostOnCtrl ? 1 : 0, RegistryValueKind.DWord);
                }
            }
            catch (Exception) { }
        }

        // Someone who had IP Hover start with Windows gets CtrlIt instead.
        static void MigrateStartup()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunPath, true))
                {
                    if (k == null || k.GetValue(OldRunName) == null) return;
                    k.DeleteValue(OldRunName, false);
                    k.SetValue(RunName, "\"" + Application.ExecutablePath + "\"");
                }
            }
            catch (Exception) { }
        }

        public static bool StartWithWindows
        {
            get
            {
                try
                {
                    using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunPath))
                    {
                        return k != null && k.GetValue(RunName) != null;
                    }
                }
                catch (Exception) { return false; }
            }
            set
            {
                try
                {
                    using (RegistryKey k = Registry.CurrentUser.CreateSubKey(RunPath))
                    {
                        if (value) k.SetValue(RunName, "\"" + Application.ExecutablePath + "\"");
                        else k.DeleteValue(RunName, false);
                    }
                }
                catch (Exception) { }
            }
        }
    }

    // ------------------------------------------------------------- IP parsing

    class IpMatch
    {
        public int Index;
        public int Length;
        public string Value;
    }

    static class IpFinder
    {
        const string Octet = @"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)";

        static readonly Regex V4 = new Regex(
            @"(?<![\w.])(?:" + Octet + @"\.){3}" + Octet + @"(?!\w|\.\d)",
            RegexOptions.Compiled);

        // Loose candidate; real validation is done by IPAddress.TryParse.
        static readonly Regex V6 = new Regex(
            @"(?<![\w:.])(?=[0-9A-Fa-f]{0,4}:)[0-9A-Fa-f:.]{3,45}(?:%[0-9A-Za-z]{1,15})?(?![\w:])",
            RegexOptions.Compiled);

        public static List<IpMatch> FindAll(string text)
        {
            List<IpMatch> list = new List<IpMatch>();
            if (string.IsNullOrEmpty(text)) return list;

            foreach (Match m in V6.Matches(text))
            {
                string v = m.Value;
                if (v.IndexOf('%') < 0) v = v.TrimEnd('.');
                if (!LooksLikeV6(v)) continue;
                IpMatch im = new IpMatch();
                im.Index = m.Index;
                im.Length = v.Length;
                im.Value = v;
                list.Add(im);
            }

            int v6Count = list.Count;
            foreach (Match m in V4.Matches(text))
            {
                bool inside = false;
                for (int i = 0; i < v6Count; i++)
                {
                    if (m.Index >= list[i].Index && m.Index < list[i].Index + list[i].Length)
                    {
                        inside = true;
                        break;
                    }
                }
                if (inside) continue;
                IpMatch im = new IpMatch();
                im.Index = m.Index;
                im.Length = m.Length;
                im.Value = m.Value;
                list.Add(im);
            }

            list.Sort(delegate(IpMatch a, IpMatch b) { return a.Index.CompareTo(b.Index); });
            return list;
        }

        // The IP whose characters span the given offset (ends inclusive), or null.
        public static IpMatch FindAt(string text, int offset)
        {
            List<IpMatch> all = FindAll(text);
            for (int i = 0; i < all.Count; i++)
            {
                if (offset >= all[i].Index && offset <= all[i].Index + all[i].Length) return all[i];
            }
            return null;
        }

        static bool LooksLikeV6(string v)
        {
            if (v.Length < 3) return false;
            int colons = 0;
            bool hex = false;
            for (int i = 0; i < v.Length; i++)
            {
                char c = v[i];
                if (c == '%') break;
                if (c == ':') colons++;
                else if (Uri.IsHexDigit(c)) hex = true;
            }
            if (colons < 2 || !hex) return false;

            string bare = v;
            int pct = bare.IndexOf('%');
            if (pct >= 0) bare = bare.Substring(0, pct);
            IPAddress a;
            if (!IPAddress.TryParse(bare, out a)) return false;
            return a.AddressFamily == AddressFamily.InterNetworkV6;
        }
    }

    // ------------------------------------------------------------ host names

    static class HostName
    {
        // Letters, digits, '-', '_' and dots only, never starting with '-',
        // so a host name is always safe to put on a command line.
        static readonly Regex Valid = new Regex(
            @"^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,62})*$",
            RegexOptions.Compiled);

        static bool IsHostChar(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '.' || c == '-' || c == '_';
        }

        // The host-name-like word that covers the given offset in text.
        public static bool TokenAt(string text, int offset, out int start, out int length)
        {
            start = 0;
            length = 0;
            if (string.IsNullOrEmpty(text)) return false;
            if (offset < 0) offset = 0;
            if (offset >= text.Length) offset = text.Length - 1;

            int i = offset;
            if (!IsHostChar(text[i]))
            {
                if (i > 0 && IsHostChar(text[i - 1])) i--;
                else return false;
            }
            int s = i, e = i + 1;
            while (s > 0 && IsHostChar(text[s - 1])) s--;
            while (e < text.Length && IsHostChar(text[e])) e++;

            // Drop sentence punctuation stuck to the ends ("see server01.")
            while (s < e && (text[s] == '.' || text[s] == '-')) s++;
            while (e > s && (text[e - 1] == '.' || text[e - 1] == '-')) e--;
            if (e - s < 1 || e - s > 253) return false;
            if (!Valid.IsMatch(text.Substring(s, e - s))) return false;

            start = s;
            length = e - s;
            return true;
        }

        // The whole of text, if it is exactly one host name.
        public static string Whole(string text)
        {
            if (text == null) return null;
            text = text.Trim();
            int st, len;
            if (text.Length == 0 || text.Length > 253) return null;
            if (!TokenAt(text, 0, out st, out len) || st != 0 || len != text.Length) return null;
            return text;
        }
    }

    // Spots Ctrl used on its own - either tapped, or held for half a second -
    // with no other key or mouse button, so Ctrl+C and friends don't count.
    static class KeyWatcher
    {
        public static volatile int Taps;

        public static void Start()
        {
            Thread t = new Thread(Run);
            t.IsBackground = true;
            t.Name = "CtrlIt key watcher";
            t.Start();
        }

        static void Run()
        {
            const int HoldMs = 500;
            bool was = false, solo = false, fired = false;
            int downAt = 0;
            while (true)
            {
                Thread.Sleep(15);
                try
                {
                    bool down = Native.IsDown(Native.VK_CONTROL);
                    if (down && !was)
                    {
                        solo = true;
                        fired = false;
                        downAt = Environment.TickCount;
                    }
                    if (down && solo)
                    {
                        for (int vk = 1; vk < 0xFF; vk++)
                        {
                            if (vk == 0x11 || vk == 0xA2 || vk == 0xA3) continue;
                            if (Native.IsDown(vk))
                            {
                                solo = false;
                                break;
                            }
                        }
                    }
                    int held = unchecked(Environment.TickCount - downAt);
                    if (down && solo && !fired && held >= HoldMs)
                    {
                        fired = true;
                        Taps++;
                    }
                    if (!down && was && solo && !fired && held < 1000) Taps++;
                    was = down;
                }
                catch (Exception) { }
            }
        }
    }

    // ------------------------------------------- reading text under the mouse

    static class Detector
    {
        static readonly int OwnPid = Process.GetCurrentProcess().Id;
        const int Context = 48;      // characters read either side of the mouse
        const int MaxFallbackText = 400;
        const int MaxFallbackIps = 4;

        // Returns the IP(s) under the given screen point, or null.
        public static List<string> Detect(Point p, bool host)
        {
            System.Windows.Point wp = new System.Windows.Point(p.X, p.Y);
            AutomationElement leaf = AutomationElement.FromPoint(wp);
            if (leaf == null) return null;
            if (leaf.Current.ProcessId == OwnPid) return null;

            // Preferred: a text control (Notepad, terminals, Word/Outlook,
            // browsers) can say exactly which characters sit under the point.
            bool textPatternWorked = false;
            AutomationElement cur = leaf;
            for (int depth = 0; depth < 8 && cur != null; depth++)
            {
                object pat;
                if (cur.TryGetCurrentPattern(TextPattern.Pattern, out pat))
                {
                    try
                    {
                        string ip = FromTextPattern((TextPattern)pat, p, wp, host);
                        textPatternWorked = true;
                        if (ip != null)
                        {
                            List<string> one = new List<string>();
                            one.Add(ip);
                            return one;
                        }
                    }
                    catch (Exception) { }
                    break;
                }
                try { cur = TreeWalker.RawViewWalker.GetParent(cur); }
                catch (Exception) { cur = null; }
            }
            if (textPatternWorked) return null;

            // Fallback: labels, list items, links, title bars etc. only expose
            // their whole text, so offer every IP found in that (short) text.
            return host ? FromElementHost(leaf) : FromElementText(leaf);
        }

        static string FromTextPattern(TextPattern tp, Point p, System.Windows.Point wp, bool host)
        {
            TextPatternRange hit = tp.RangeFromPoint(wp);
            if (hit == null) return null;

            // Collapse to a caret position at the start of whatever came back.
            TextPatternRange caret = hit.Clone();
            caret.MoveEndpointByRange(TextPatternRangeEndpoint.End, caret, TextPatternRangeEndpoint.Start);

            TextPatternRange before = caret.Clone();
            before.MoveEndpointByUnit(TextPatternRangeEndpoint.Start, TextUnit.Character, -Context);
            TextPatternRange after = caret.Clone();
            after.MoveEndpointByUnit(TextPatternRangeEndpoint.End, TextUnit.Character, Context);

            string pre = before.GetText(Context * 2) ?? "";
            string post = after.GetText(Context * 2) ?? "";
            string text = pre + post;
            int offset = pre.Length;

            int mIndex, mLength;
            string found;
            if (host)
            {
                if (!HostName.TokenAt(text, offset, out mIndex, out mLength)) return null;
                found = text.Substring(mIndex, mLength);
            }
            else
            {
                IpMatch m = IpFinder.FindAt(text, offset);
                if (m == null) return null;
                mIndex = m.Index;
                mLength = m.Length;
                found = m.Value;
            }

            // RangeFromPoint answers with the *nearest* text even when the mouse
            // is over blank space, so confirm the IP really is under the mouse.
            try
            {
                TextPatternRange ipRange = caret.Clone();
                int back = offset - mIndex;
                int fwd = mIndex + mLength - offset;
                if (back > 0) ipRange.MoveEndpointByUnit(TextPatternRangeEndpoint.Start, TextUnit.Character, -back);
                if (fwd > 0) ipRange.MoveEndpointByUnit(TextPatternRangeEndpoint.End, TextUnit.Character, fwd);
                System.Windows.Rect[] rects = ipRange.GetBoundingRectangles();
                if (rects != null && rects.Length > 0)
                {
                    bool over = false;
                    for (int i = 0; i < rects.Length; i++)
                    {
                        System.Windows.Rect r = rects[i];
                        if (r.IsEmpty) continue;
                        if (p.X >= r.X - 5 && p.X <= r.X + r.Width + 5 &&
                            p.Y >= r.Y - 5 && p.Y <= r.Y + r.Height + 5)
                        {
                            over = true;
                            break;
                        }
                    }
                    if (!over) return null;
                }
            }
            catch (Exception) { }

            return found;
        }

        // Labels, list/grid items and links that hold just one host name.
        static List<string> FromElementHost(AutomationElement el)
        {
            ControlType ct;
            string name;
            try
            {
                ct = el.Current.ControlType;
                name = el.Current.Name;
            }
            catch (Exception) { return null; }
            if (ct != ControlType.Text && ct != ControlType.ListItem && ct != ControlType.DataItem &&
                ct != ControlType.Hyperlink && ct != ControlType.TreeItem && ct != ControlType.HeaderItem)
                return null;
            string h = HostName.Whole(name);
            if (h == null) return null;
            List<string> one = new List<string>();
            one.Add(h);
            return one;
        }

        static List<string> FromElementText(AutomationElement el)
        {
            List<string> result = new List<string>();

            string name = null;
            try { name = el.Current.Name; }
            catch (Exception) { }
            AddIps(result, name);

            if (result.Count == 0)
            {
                string value = null;
                try
                {
                    object vp;
                    if (el.TryGetCurrentPattern(ValuePattern.Pattern, out vp))
                        value = ((ValuePattern)vp).Current.Value;
                }
                catch (Exception) { }
                AddIps(result, value);
            }

            return result.Count > 0 ? result : null;
        }

        static void AddIps(List<string> result, string text)
        {
            if (string.IsNullOrEmpty(text) || text.Length > MaxFallbackText) return;
            List<IpMatch> found = IpFinder.FindAll(text);
            for (int i = 0; i < found.Count && result.Count < MaxFallbackIps; i++)
            {
                if (!result.Contains(found[i].Value)) result.Add(found[i].Value);
            }
        }
    }

    // ------------------------------------------- reading text off the screen
    //
    // Terminals such as Command Prompt (on some Windows 10 builds) and
    // MobaXterm draw their own text and do not tell Windows what it says, so
    // when the normal route finds nothing we take a small picture of the area
    // around the mouse and let Windows' built-in text recognition read it.

#if OCR
    static class ScreenReader
    {
        const int CaptureWidth = 460;
        const int CaptureHeight = 64;
        const int Scale = 2;          // small console fonts recognise better enlarged

        static global::Windows.Media.Ocr.OcrEngine engine;
        static bool triedEngine;
        public static volatile string Problem;   // set when screen reading cannot be used

        static bool EnsureEngine()
        {
            if (triedEngine) return engine != null;
            triedEngine = true;
            engine = global::Windows.Media.Ocr.OcrEngine.TryCreateFromUserProfileLanguages();
            if (engine == null)
            {
                foreach (global::Windows.Globalization.Language lang in
                    global::Windows.Media.Ocr.OcrEngine.AvailableRecognizerLanguages)
                {
                    engine = global::Windows.Media.Ocr.OcrEngine.TryCreateFromLanguage(lang);
                    if (engine != null) break;
                }
            }
            if (engine == null) Problem = "No Windows text-recognition (OCR) language is installed.";
            return engine != null;
        }

        // Returns the IP address drawn under the given screen point, or null.
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
        public static string Detect(Point p, bool allowHost, out bool isHost)
        {
            isHost = false;
            if (!EnsureEngine()) return null;

            Rectangle cap = new Rectangle(p.X - CaptureWidth / 2, p.Y - CaptureHeight / 2, CaptureWidth, CaptureHeight);
            cap.Intersect(SystemInformation.VirtualScreen);
            if (cap.Width < 24 || cap.Height < 10) return null;

            int bw = cap.Width * Scale;
            int bh = cap.Height * Scale;
            byte[] px;

            using (Bitmap raw = new Bitmap(cap.Width, cap.Height, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            using (Bitmap big = new Bitmap(bw, bh, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            {
                using (Graphics g = Graphics.FromImage(raw))
                {
                    g.CopyFromScreen(cap.Location, Point.Empty, cap.Size);
                }
                using (Graphics g = Graphics.FromImage(big))
                {
                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                    g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.Half;
                    g.DrawImage(raw, new Rectangle(0, 0, bw, bh), new Rectangle(0, 0, cap.Width, cap.Height), GraphicsUnit.Pixel);
                }
                System.Drawing.Imaging.BitmapData bd = big.LockBits(new Rectangle(0, 0, bw, bh),
                    System.Drawing.Imaging.ImageLockMode.ReadOnly, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                try
                {
                    px = new byte[bw * bh * 4];
                    for (int y = 0; y < bh; y++)
                    {
                        Marshal.Copy(new IntPtr(bd.Scan0.ToInt64() + (long)y * bd.Stride), px, y * bw * 4, bw * 4);
                    }
                }
                finally { big.UnlockBits(bd); }
            }

            // Recognition is better on dark-on-light, so flip dark terminals.
            long sum = 0;
            int samples = 0;
            for (int i = 0; i + 2 < px.Length; i += 4 * 7)
            {
                sum += px[i] + px[i + 1] + px[i + 2];
                samples += 3;
            }
            bool dark = samples > 0 && sum / samples < 110;
            for (int i = 0; i + 3 < px.Length; i += 4)
            {
                if (dark)
                {
                    px[i] = (byte)(255 - px[i]);
                    px[i + 1] = (byte)(255 - px[i + 1]);
                    px[i + 2] = (byte)(255 - px[i + 2]);
                }
                px[i + 3] = 255;
            }

            global::Windows.Media.Ocr.OcrResult result;
            global::Windows.Graphics.Imaging.SoftwareBitmap sb = new global::Windows.Graphics.Imaging.SoftwareBitmap(
                global::Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8, bw, bh,
                global::Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied);
            try
            {
                sb.CopyFromBuffer(global::Windows.Security.Cryptography.CryptographicBuffer.CreateFromByteArray(px));
                global::Windows.Foundation.IAsyncOperation<global::Windows.Media.Ocr.OcrResult> op = engine.RecognizeAsync(sb);
                int waited = 0;
                while (op.Status == global::Windows.Foundation.AsyncStatus.Started && waited < 3000)
                {
                    Thread.Sleep(5);
                    waited += 5;
                }
                if (op.Status != global::Windows.Foundation.AsyncStatus.Completed) return null;
                result = op.GetResults();
            }
            finally { sb.Dispose(); }
            if (result == null) return null;

            double cx = (p.X - cap.X) * Scale;
            double cy = (p.Y - cap.Y) * Scale;
            double slack = 5 * Scale;

            foreach (global::Windows.Media.Ocr.OcrLine line in result.Lines)
            {
                // Rebuild the line, remembering which recognised word each
                // character came from so a match can be traced to a position.
                System.Text.StringBuilder text = new System.Text.StringBuilder();
                List<int> owner = new List<int>();
                List<double[]> boxes = new List<double[]>();

                foreach (global::Windows.Media.Ocr.OcrWord word in line.Words)
                {
                    string t = Tidy(word.Text);
                    if (string.IsNullOrEmpty(t)) continue;
                    global::Windows.Foundation.Rect r = word.BoundingRect;
                    boxes.Add(new double[] { r.X, r.Y, r.X + r.Width, r.Y + r.Height });

                    if (text.Length > 0)
                    {
                        // "192.168. 1.10" - recognition sometimes inserts a gap after a dot.
                        char prev = text[text.Length - 1];
                        bool glue = (prev == '.' && char.IsDigit(t[0])) || (t[0] == '.' && char.IsDigit(prev));
                        if (!glue)
                        {
                            text.Append(' ');
                            owner.Add(-1);
                        }
                    }
                    for (int i = 0; i < t.Length; i++)
                    {
                        text.Append(t[i]);
                        owner.Add(boxes.Count - 1);
                    }
                }

                List<IpMatch> found = IpFinder.FindAll(text.ToString());
                for (int m = 0; m < found.Count; m++)
                {
                    double left = double.MaxValue, top = double.MaxValue, right = double.MinValue, bottom = double.MinValue;
                    for (int i = found[m].Index; i < found[m].Index + found[m].Length && i < owner.Count; i++)
                    {
                        if (owner[i] < 0) continue;
                        double[] b = boxes[owner[i]];
                        if (b[0] < left) left = b[0];
                        if (b[1] < top) top = b[1];
                        if (b[2] > right) right = b[2];
                        if (b[3] > bottom) bottom = b[3];
                    }
                    if (cx >= left - slack && cx <= right + slack && cy >= top - slack && cy <= bottom + slack)
                        return found[m].Value;
                }
            }
            // No IP there: if asked, take the word under the mouse as a host name.
            if (allowHost)
            {
                global::Windows.Media.Ocr.OcrWord best = null;
                double bestDist = double.MaxValue;
                double near = 3 * Scale;
                foreach (global::Windows.Media.Ocr.OcrLine ln in result.Lines)
                {
                    foreach (global::Windows.Media.Ocr.OcrWord wd in ln.Words)
                    {
                        global::Windows.Foundation.Rect wr = wd.BoundingRect;
                        if (cy < wr.Y - near || cy > wr.Y + wr.Height + near) continue;
                        double dist = cx < wr.X ? wr.X - cx : (cx > wr.X + wr.Width ? cx - (wr.X + wr.Width) : 0);
                        if (dist > near || dist >= bestDist) continue;
                        bestDist = dist;
                        best = wd;
                    }
                }
                if (best != null && !string.IsNullOrEmpty(best.Text))
                {
                    global::Windows.Foundation.Rect br = best.BoundingRect;
                    string wt = best.Text;
                    int at = br.Width > 0 ? (int)((cx - br.X) / br.Width * wt.Length) : 0;
                    int hs, hn;
                    if (HostName.TokenAt(wt, at, out hs, out hn))
                    {
                        isHost = true;
                        return wt.Substring(hs, hn);
                    }
                }
            }
            return null;
        }

        // Fix the usual misreads (O for 0, l for 1, comma for dot) in words
        // that are otherwise made of digits and dots. Length is preserved.
        static string Tidy(string w)
        {
            if (string.IsNullOrEmpty(w)) return w;
            bool digit = false, dot = false;
            for (int i = 0; i < w.Length; i++)
            {
                char c = w[i];
                if (c >= '0' && c <= '9') digit = true;
                else if (c == '.' || c == ',') dot = true;
                else if ("OoIl|:".IndexOf(c) < 0) return w;
            }
            if (!digit || !dot) return w;
            char[] a = w.ToCharArray();
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == 'O' || a[i] == 'o') a[i] = '0';
                else if (a[i] == 'I' || a[i] == 'l' || a[i] == '|') a[i] = '1';
                else if (a[i] == ',') a[i] = '.';
            }
            return new string(a);
        }
    }
#endif

    // ---------------------------------------------------------------- actions

    static class Actions
    {
        public static void Ping(string ip) { RunInConsole("Ping", "ping", ip); }
        public static void PingName(string ip) { RunInConsole("Ping -a", "ping -a", ip); }
        public static void Trace(string ip) { RunInConsole("Traceroute", "tracert", ip); }
        public static void PathPing(string ip) { RunInConsole("Pathping", "pathping", ip); }

        // Asks for the username in the console window, then connects.
        public static void Ssh(string ip)
        {
            Start("cmd.exe", "/v:on /k title SSH " + ip + " & set u=& set /p u=SSH username for " + ip +
                ": & ssh !u!@" + ip, "SSH");
        }

        public static void Http(string ip) { Start("http://" + Bracketed(ip) + "/", null, "the browser"); }
        public static void Https(string ip) { Start("https://" + Bracketed(ip) + "/", null, "the browser"); }

        public static void Share(string ip)
        {
            Start("explorer.exe", "\\\\" + UncHost(ip), "the file share");
        }

        // Windows cannot use a raw IPv6 address in a \\server path; it has
        // a special spelling for that.
        static string UncHost(string ip)
        {
            if (ip.IndexOf(':') < 0) return ip;
            return ip.Replace(':', '-').Replace('%', 's') + ".ipv6-literal.net";
        }

        // ---- Sysinternals PsTools (not part of Windows, so found on disk or
        //      run from Microsoft's official Sysinternals Live share)

        public static void PsExecCmd(string ip) { RunPsTool("PsExec", "PsExec", ip, "cmd"); }
        public static void PsExecIpconfig(string ip) { RunPsTool("PsExec ipconfig", "PsExec", ip, "ipconfig /all"); }
        public static void PsInfo(string ip) { RunPsTool("PsInfo", "PsInfo", ip, "-d"); }
        public static void PsLoggedOn(string ip) { RunPsTool("PsLoggedOn", "PsLoggedon", ip, ""); }
        public static void PsList(string ip) { RunPsTool("PsList", "pslist", ip, ""); }
        public static void PsService(string ip) { RunPsTool("PsService", "PsService", ip, "query"); }

        public static void RunPowerShell(string title, string target, string body, bool remote)
        {
            string script = PsScripts.Build(title, target, body, remote);
            string encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
            Start("powershell.exe", "-NoExit -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded, "PowerShell");
        }

        static void RunPsTool(string title, string tool, string ip, string args)
        {
            string exe = FindTool(tool);
            bool live = exe == null;
            if (live) exe = "\\\\live.sysinternals.com\\tools\\" + tool + ".exe";

            string cmd = "/k title " + title + " " + ip + (live ? " (from Sysinternals Live)" : "") +
                " & \"" + exe + "\" -accepteula \\\\" + UncHost(ip) + (args.Length > 0 ? " " + args : "");
            if (live)
            {
                cmd += " & echo. & echo " + tool + " was not found on this PC, so it was run from live.sysinternals.com." +
                       " & echo If that failed, download PsTools from Microsoft and put it in a folder on PATH" +
                       " or next to ctrlit.exe.";
            }
            Start("cmd.exe", cmd, title);
        }

        static string FindTool(string tool)
        {
            List<string> names = new List<string>();
            if (Environment.Is64BitOperatingSystem) names.Add(tool + "64.exe");
            names.Add(tool + ".exe");

            List<string> dirs = new List<string>();
            try { dirs.Add(System.IO.Path.GetDirectoryName(Application.ExecutablePath)); }
            catch (Exception) { }
            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string d in path.Split(';')) dirs.Add(d.Trim().Trim('"'));
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            dirs.Add(@"C:\PSTools");
            dirs.Add(@"C:\Tools");
            dirs.Add(@"C:\Tools\PSTools");
            dirs.Add(@"C:\Sysinternals");
            dirs.Add(@"C:\SysinternalsSuite");
            dirs.Add(System.IO.Path.Combine(pf, "Sysinternals"));
            dirs.Add(System.IO.Path.Combine(pf, "SysinternalsSuite"));
            dirs.Add(System.IO.Path.Combine(pf, "PSTools"));
            dirs.Add(System.IO.Path.Combine(home, @"Downloads\PSTools"));
            dirs.Add(System.IO.Path.Combine(home, @"Downloads\SysinternalsSuite"));

            foreach (string d in dirs)
            {
                if (string.IsNullOrEmpty(d)) continue;
                foreach (string n in names)
                {
                    try
                    {
                        string f = System.IO.Path.Combine(d, n);
                        if (System.IO.File.Exists(f)) return f;
                    }
                    catch (Exception) { }
                }
            }
            return null;
        }

        static string Bracketed(string ip)
        {
            if (ip.IndexOf(':') < 0) return ip;
            int pct = ip.IndexOf('%');
            if (pct >= 0) ip = ip.Substring(0, pct);
            return "[" + ip + "]";
        }

        static void Start(string file, string args, string what)
        {
            try
            {
                ProcessStartInfo psi = args == null ? new ProcessStartInfo(file) : new ProcessStartInfo(file, args);
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not open " + what + ": " + ex.Message, "CtrlIt");
            }
        }
        public static void Reverse(string ip) { RunInConsole("Reverse lookup", "nslookup", ip); }

        public static void Rdp(string ip)
        {
            try
            {
                // mstsc wants IPv6 addresses in square brackets.
                string target = ip.IndexOf(':') >= 0 ? "[" + ip + "]" : ip;
                ProcessStartInfo psi = new ProcessStartInfo("mstsc.exe", "/v:" + target);
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not start Remote Desktop: " + ex.Message, "CtrlIt");
            }
        }

        public static void Copy(string ip)
        {
            try { Clipboard.SetText(ip); }
            catch (Exception) { }
        }

        // ip has already been validated as an IP address, so it is safe to
        // place on a command line.
        static void RunInConsole(string title, string command, string ip)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                    "/k title " + title + " " + ip + " & " + command + " " + ip);
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not start " + command + ": " + ex.Message, "CtrlIt");
            }
        }
    }

    // ------------------------------------------------- PowerShell diagnostics
    //
    // Each command runs in its own PowerShell window. "Local" ones run on this
    // PC against the target; "remote" ones run on the target itself through
    // remote PowerShell (WinRM), or directly when the target is this PC.

    static class PsScripts
    {
        const string LocalHeader = @"
$ErrorActionPreference = 'Continue'
$target = '{T}'
$Host.UI.RawUI.WindowTitle = '{TITLE} - ' + $target
try {
    $raw = $Host.UI.RawUI
    $bs = $raw.BufferSize
    if ($bs.Width -lt 200) { $bs.Width = 200; $raw.BufferSize = $bs }
    $ws = $raw.WindowSize
    $ws.Width = [Math]::Min(200, $raw.MaxPhysicalWindowSize.Width)
    $raw.WindowSize = $ws
} catch {}
function Get-TargetAddresses {
    $plain = ($target -split '%')[0]
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($plain, [ref]$parsed)) { return @($plain) }
    @(Resolve-DnsName $target -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
}
Write-Host ''
Write-Host ('{TITLE} - ' + $target) -ForegroundColor Cyan
";

        const string RemoteExtra = @"
$names = @('localhost', '127.0.0.1', '::1', $env:COMPUTERNAME)
if ($env:USERDNSDOMAIN) { $names += ($env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN) }
$isLocal = $false
foreach ($n in $names) { if ($n -eq $target) { $isLocal = $true } }
if (-not $isLocal) {
    try {
        if (@(Get-NetIPAddress -ErrorAction Stop | ForEach-Object { $_.IPAddress }) -contains (($target -split '%')[0])) { $isLocal = $true }
    } catch {}
}
$remote = $target
if ($isLocal) {
    Write-Host 'This is the local computer.' -ForegroundColor DarkGray
} else {
    $plain = ($target -split '%')[0]
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($plain, [ref]$parsed)) {
        try {
            $name = [System.Net.Dns]::GetHostEntry($plain).HostName
            if ($name -and $name -ne $plain) {
                $remote = $name
                Write-Host ('Using the name ' + $name + ' for remote PowerShell.') -ForegroundColor DarkGray
            }
        } catch {
            Write-Host ('No name found for ' + $plain + ' - remote PowerShell to a bare IP address only works if it is in WinRM TrustedHosts.') -ForegroundColor Yellow
        }
    }
    Write-Host ('Running on ' + $remote + ' via remote PowerShell (WinRM)...') -ForegroundColor DarkGray
}
Write-Host ''
function On([scriptblock]$sb) {
    if ($isLocal) { & $sb; return }
    $errs = $null
    try {
        Invoke-Command -ComputerName $remote -ScriptBlock $sb -ErrorVariable errs -ErrorAction SilentlyContinue
    } catch {
        $errs = @($_)
    }
    $noConnect = $false
    foreach ($e in $errs) {
        Write-Host $e -ForegroundColor Red
        $ex = $e.Exception
        while ($ex) {
            if ($ex -is [System.Management.Automation.Remoting.PSRemotingTransportException]) { $noConnect = $true }
            $ex = $ex.InnerException
        }
    }
    if ($noConnect) {
        Write-Host ''
        Write-Host ('Could not connect to ' + $remote + ' with remote PowerShell. It needs WinRM enabled there (Enable-PSRemoting), admin rights on it, and for a bare IP address an entry in WinRM TrustedHosts.') -ForegroundColor Yellow
    }
}
";

        const string Footer = @"
Write-Host ''
Write-Host 'Done.' -ForegroundColor DarkGray
";

        public static string Build(string title, string target, string body, bool remote)
        {
            string head = remote ? LocalHeader + RemoteExtra : LocalHeader + "\nWrite-Host ''\n";
            return head.Replace("{TITLE}", title).Replace("{T}", target) + "\n" + body + "\n" + Footer;
        }

        // ---- run on this PC, towards the target

        public const string TcpPort = @"
$p = Read-Host ('TCP port to test on ' + $target + ' [443]')
if (-not $p) { $p = 443 }
Test-NetConnection -ComputerName $target -Port $p -InformationLevel Detailed
";

        public const string CommonPorts = @"
$ports = 21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306, 3389, 5432, 5985, 5986, 8080, 8443
Write-Host ('Testing ' + $ports.Count + ' common TCP ports (3 second timeout)...')
$tests = @()
foreach ($p in $ports) {
    $c = New-Object System.Net.Sockets.TcpClient
    $t = $null
    try { $t = $c.ConnectAsync($target, $p) } catch {}
    $tests += ,@($p, $c, $t)
}
$deadline = (Get-Date).AddSeconds(3)
foreach ($x in $tests) {
    $left = [int][Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds)
    $ok = $false
    try { if ($x[2] -ne $null) { $ok = $x[2].Wait($left) -and $x[2].Status -eq 'RanToCompletion' } } catch {}
    if ($ok) { Write-Host ('  {0,-6} open' -f $x[0]) -ForegroundColor Green }
    else { Write-Host ('  {0,-6} closed or filtered' -f $x[0]) -ForegroundColor DarkGray }
    $x[1].Close()
}
";

        public const string Dns = @"
Resolve-DnsName $target | Format-Table -AutoSize | Out-String -Width 200
";

        public const string DnsA = @"
Resolve-DnsName $target -Type A | Format-Table -AutoSize | Out-String -Width 200
";

        public const string DnsServer = @"
$s = Read-Host 'DNS server to ask (name or IP address)'
if ($s) { Resolve-DnsName $target -Server $s | Format-Table -AutoSize | Out-String -Width 200 }
";

        public const string Connections = @"
$addrs = Get-TargetAddresses
if (-not $addrs) { Write-Host 'Could not resolve that name.' -ForegroundColor Yellow; return }
Write-Host ('Addresses: ' + ($addrs -join ', '))
$conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $addrs -contains $_.RemoteAddress -or $addrs -contains $_.LocalAddress })
if ($conns.Count -eq 0) {
    Write-Host 'No TCP connections between this PC and that address right now.'
} else {
    $conns | Sort-Object State, RemotePort |
        Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Format-Table -AutoSize | Out-String -Width 200
}
";

        public const string Route = @"
$addrs = Get-TargetAddresses
if (-not $addrs) { Write-Host 'Could not resolve that name.' -ForegroundColor Yellow; return }
foreach ($a in $addrs) { Find-NetRoute -RemoteIPAddress $a | Format-List | Out-String -Width 200 }
";

        public const string Neighbor = @"
$addrs = Get-TargetAddresses
if (-not $addrs) { Write-Host 'Could not resolve that name.' -ForegroundColor Yellow; return }
foreach ($a in $addrs) {
    Test-Connection -ComputerName $a -Count 1 -Quiet | Out-Null
    $n = Get-NetNeighbor -IPAddress $a -ErrorAction SilentlyContinue
    if ($n) { $n | Format-Table IPAddress, LinkLayerAddress, State, InterfaceAlias -AutoSize | Out-String -Width 200 }
    else { Write-Host ($a + ' is not in the ARP / neighbour cache - it is probably not on the same network segment, so traffic to it goes via a router.') }
}
";

        // ---- run on the target

        public const string IpConfig = @"
On { Get-NetIPConfiguration -Detailed | Out-String -Width 200 }
";

        public const string Adapters = @"
On { Get-NetAdapter | Sort-Object Name | Format-Table Name, InterfaceDescription, Status, LinkSpeed, MacAddress -AutoSize | Out-String -Width 200 }
";

        public const string NicStats = @"
On {
    Get-NetAdapterStatistics | Sort-Object Name |
        Format-Table Name, ReceivedBytes, SentBytes, ReceivedDiscardedPackets, ReceivedPacketErrors, OutboundDiscardedPackets, OutboundPacketErrors -AutoSize |
        Out-String -Width 200
}
";

        public const string Routes = @"
On { Get-NetRoute | Sort-Object AddressFamily, DestinationPrefix | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias -AutoSize | Out-String -Width 200 }
";

        public const string Arp = @"
On {
    Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } | Sort-Object AddressFamily, IPAddress |
        Format-Table IPAddress, LinkLayerAddress, State, InterfaceAlias -AutoSize | Out-String -Width 200
}
";

        public const string Listening = @"
On {
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Format-Table -AutoSize | Out-String -Width 200
}
";

        public const string Established = @"
On {
    Get-NetTCPConnection -State Established | Sort-Object RemoteAddress, RemotePort |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Format-Table -AutoSize | Out-String -Width 200
}
";

        public const string FwProfiles = @"
On { Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize | Out-String -Width 200 }
";

        public const string FwRules = @"
On {
    Get-NetFirewallRule -Enabled True | Sort-Object Direction, DisplayName |
        Format-Table DisplayName, Direction, Action, Profile -AutoSize | Out-String -Width 200
}
";

        public const string OsInfo = @"
On { Get-ComputerInfo | Format-List | Out-String -Width 200 }
";

        public const string Hotfixes = @"
On { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn, InstalledBy -AutoSize | Out-String -Width 200 }
";

        public const string Processes = @"
On {
    Get-Process | Sort-Object CPU -Descending |
        Format-Table Id, ProcessName, @{n='CPU(s)'; e={ [Math]::Round($_.CPU, 1) }},
            @{n='Memory(MB)'; e={ [Math]::Round($_.WorkingSet64 / 1MB) }}, Handles -AutoSize |
        Out-String -Width 200
}
";

        public const string Services = @"
On { Get-Service | Sort-Object Status, DisplayName | Format-Table Status, StartType, Name, DisplayName -AutoSize | Out-String -Width 200 }
";

        public const string StoppedAuto = @"
On {
    $s = @(Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' })
    if ($s.Count -eq 0) { 'All automatic services are running.' }
    else { $s | Sort-Object DisplayName | Format-Table Status, Name, DisplayName -AutoSize | Out-String -Width 200 }
}
";

        public const string Events = @"
On {
    $f = @{ LogName = 'System', 'Application'; Level = 1, 2, 3; StartTime = (Get-Date).AddHours(-24) }
    $ev = @(Get-WinEvent -FilterHashtable $f -MaxEvents 300 -ErrorAction SilentlyContinue)
    if ($ev.Count -eq 0) { 'No errors or warnings in the System and Application logs in the last 24 hours.' }
    else {
        $ev | Format-Table TimeCreated, LogName, LevelDisplayName, Id, ProviderName,
            @{n='Message'; e={ ($_.Message -split ""`r?`n"")[0] }} -AutoSize | Out-String -Width 250
    }
}
";

        public const string Perf = @"
On {
    $c = '\Processor(_Total)\% Processor Time', '\Memory\Available MBytes', '\PhysicalDisk(*)\Avg. Disk sec/Read', '\PhysicalDisk(*)\Avg. Disk sec/Write'
    'Sampling CPU, memory and disk latency 5 times, 2 seconds apart (disk latency is in seconds)...'
    (Get-Counter -Counter $c -SampleInterval 2 -MaxSamples 5).CounterSamples |
        Select-Object Timestamp, Path, @{n='Value'; e={ [Math]::Round($_.CookedValue, 4) }} |
        Format-Table -AutoSize | Out-String -Width 200
}
";

        public const string Disks = @"
On {
    '=== Disks ==='
    Get-Disk | Format-Table Number, FriendlyName, OperationalStatus, HealthStatus, PartitionStyle,
        @{n='Size(GB)'; e={ [Math]::Round($_.Size / 1GB) }} -AutoSize | Out-String -Width 200
    '=== Volumes ==='
    Get-Volume | Sort-Object DriveLetter | Format-Table DriveLetter, FileSystemLabel, FileSystem, HealthStatus,
        @{n='Size(GB)'; e={ [Math]::Round($_.Size / 1GB, 1) }}, @{n='Free(GB)'; e={ [Math]::Round($_.SizeRemaining / 1GB, 1) }} -AutoSize |
        Out-String -Width 200
    '=== Physical disks ==='
    Get-PhysicalDisk | Format-Table FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus,
        @{n='Size(GB)'; e={ [Math]::Round($_.Size / 1GB) }} -AutoSize | Out-String -Width 200
}
";

        public const string StorageHealth = @"
On {
    foreach ($d in Get-PhysicalDisk) {
        '=== ' + $d.FriendlyName + ' ==='
        $d | Get-StorageReliabilityCounter | Format-List | Out-String -Width 200
    }
}
";

        const string ClusterCheck = @"
    if (-not (Get-Module -ListAvailable FailoverClusters)) { 'The Failover Clustering tools are not installed on ' + $env:COMPUTERNAME + '.'; return }
    Import-Module FailoverClusters
";

        public const string Cluster = "On {" + ClusterCheck + @"
    Get-Cluster | Format-List Name, Domain | Out-String -Width 200
    '=== Quorum ==='
    Get-ClusterQuorum | Format-List | Out-String -Width 200
    '=== Roles ==='
    Get-ClusterGroup | Format-Table Name, State, OwnerNode -AutoSize | Out-String -Width 200
}
";

        public const string ClusterNodes = "On {" + ClusterCheck + @"
    Get-ClusterNode | Format-Table Name, State, NodeWeight, DynamicWeight -AutoSize | Out-String -Width 200
}
";

        public const string ClusterResources = "On {" + ClusterCheck + @"
    Get-ClusterResource | Sort-Object OwnerGroup, Name | Format-Table Name, State, OwnerGroup, OwnerNode, ResourceType -AutoSize | Out-String -Width 200
}
";

    }

    // ------------------------------------------------------------------ popup

    class IpPopup : Form
    {
        const int HotkeyId = 1;
        const int WM_HOTKEY = 0x0312;
        const int WM_MOUSEACTIVATE = 0x0021;

        readonly TableLayoutPanel table;
        readonly System.Windows.Forms.Timer watch;
        readonly object boundsLock = new object();
        Rectangle shownBounds = Rectangle.Empty;
        Point anchor;
        Font ipFont;
        ContextMenuStrip subMenu;
        Button subMenuOwner;

        public event EventHandler HotkeyPressed;

        public IpPopup()
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            TopMost = true;
            BackColor = Color.White;
            Font = SystemFonts.MessageBoxFont;
            ipFont = new Font("Consolas", Font.SizeInPoints + 1f, FontStyle.Bold);

            table = new TableLayoutPanel();
            table.AutoSize = true;
            table.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            table.Location = new Point(1, 1);
            table.Padding = new Padding(4, 3, 4, 3);
            table.BackColor = Color.White;
            Controls.Add(table);

            watch = new System.Windows.Forms.Timer();
            watch.Interval = 50;
            watch.Tick += delegate { CheckMouseAway(); };
        }

        // Never take keyboard focus away from whatever the user is working in.
        protected override bool ShowWithoutActivation { get { return true; } }

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ExStyle |= 0x08000000; // WS_EX_NOACTIVATE
                cp.ExStyle |= 0x00000080; // WS_EX_TOOLWINDOW
                cp.ExStyle |= 0x00000008; // WS_EX_TOPMOST
                cp.ClassStyle |= 0x00020000; // CS_DROPSHADOW
                return cp;
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            // Ctrl+Alt+I : look up an IP that is on the clipboard.
            Native.RegisterHotKey(Handle, HotkeyId, 0x0001 | 0x0002, (uint)Keys.I);
        }

        protected override void OnHandleDestroyed(EventArgs e)
        {
            Native.UnregisterHotKey(Handle, HotkeyId);
            base.OnHandleDestroyed(e);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_MOUSEACTIVATE)
            {
                m.Result = new IntPtr(3); // MA_NOACTIVATE
                return;
            }
            if (m.Msg == WM_HOTKEY && m.WParam.ToInt32() == HotkeyId)
            {
                EventHandler h = HotkeyPressed;
                if (h != null) h(this, EventArgs.Empty);
                return;
            }
            base.WndProc(ref m);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using (Pen pen = new Pen(Color.FromArgb(120, 120, 120)))
            {
                e.Graphics.DrawRectangle(pen, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
            }
        }

        // Called from the background thread to avoid re-scanning our own popup.
        public bool ContainsPoint(Point p)
        {
            lock (boundsLock) { return shownBounds.Contains(p); }
        }

        public void ShowFor(List<string> ips, bool isHost, Point at)
        {
            if (ips == null || ips.Count == 0) return;
            anchor = at;

            table.SuspendLayout();
            while (table.Controls.Count > 0)
            {
                Control c = table.Controls[0];
                table.Controls.RemoveAt(0);
                c.Dispose();
            }
            table.RowStyles.Clear();
            table.ColumnStyles.Clear();
            table.ColumnCount = ips.Count;
            table.RowCount = 15;

            for (int col = 0; col < ips.Count; col++)
            {
                string ip = ips[col];

                Label label = new Label();
                label.Text = isHost ? ip + "   (hostname)" : ip;
                label.Font = ipFont;
                label.AutoSize = true;
                label.Anchor = AnchorStyles.Left;
                label.Margin = new Padding(6, 4, 10, 4);
                table.Controls.Add(label, col, 0);

                int row = 1;
                table.Controls.Add(MakeButton("Ping", ip, Actions.Ping), col, row++);
                table.Controls.Add(MakeButton(isHost ? "Ping -a" : "Ping -a (resolve name)", ip, Actions.PingName), col, row++);
                table.Controls.Add(MakeButton("Traceroute", ip, Actions.Trace), col, row++);
                table.Controls.Add(MakeButton("Pathping", ip, Actions.PathPing), col, row++);
                table.Controls.Add(MakeButton(isHost ? "Nslookup" : "Nslookup (reverse lookup)", ip, Actions.Reverse), col, row++);
                table.Controls.Add(MakeButton("RDP", ip, Actions.Rdp), col, row++);
                table.Controls.Add(MakeButton("SSH", ip, Actions.Ssh), col, row++);
                table.Controls.Add(MakeButton("Open in browser (http)", ip, Actions.Http), col, row++);
                table.Controls.Add(MakeButton("Open in browser (https)", ip, Actions.Https), col, row++);
                table.Controls.Add(MakeButton("Open file share", ip, Actions.Share), col, row++);
                table.Controls.Add(MakeSubmenuButton("Network tests", ip, FillNetTests), col, row++);
                table.Controls.Add(MakeSubmenuButton("Remote PowerShell", ip, FillRemote), col, row++);
                table.Controls.Add(MakeSubmenuButton("PsTools", ip, FillPsTools), col, row++);
                table.Controls.Add(MakeButton("Copy", ip, Actions.Copy), col, row++);
            }
            table.ResumeLayout(true);

            Size want = table.PreferredSize;
            ClientSize = new Size(want.Width + 2, want.Height + 2);

            // Just below-right of the mouse, kept on the same screen.
            Rectangle area = Screen.FromPoint(at).WorkingArea;
            int x = at.X + 14;
            int y = at.Y + 18;
            if (x + Width > area.Right) x = area.Right - Width;
            if (x < area.Left) x = area.Left;
            if (y + Height > area.Bottom) y = at.Y - Height - 10;
            if (y < area.Top) y = area.Top;
            Location = new Point(x, y);

            if (!Visible) Show();
            Native.SetWindowPos(Handle, new IntPtr(-1), x, y, 0, 0, 0x0001 | 0x0010); // topmost, no size, no activate
            Invalidate();

            lock (boundsLock) { shownBounds = Bounds; }
            watch.Start();
        }

        public void HidePopup()
        {
            if (subMenu != null && subMenu.Visible) subMenu.Close();
            watch.Stop();
            lock (boundsLock) { shownBounds = Rectangle.Empty; }
            if (Visible) Hide();
        }

        Button MakeButton(string text, string ip, Action<string> action)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 0;
            b.TextAlign = ContentAlignment.MiddleLeft;
            b.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            b.FlatAppearance.MouseOverBackColor = Color.FromArgb(220, 235, 252);
            b.BackColor = Color.White;
            b.Padding = new Padding(2, 0, 8, 0);
            b.Margin = new Padding(0);
            b.TabStop = false;
            b.Cursor = Cursors.Hand;
            if (action != null)
            {
                b.Click += delegate
                {
                    HidePopup();
                    action(ip);
                };
            }
            return b;
        }

        // ---- submenus (PsTools, Network tests, Remote PowerShell)

        Button MakeSubmenuButton(string text, string ip, Action<ToolStripItemCollection, string> fill)
        {
            Button b = MakeButton(text + "  \u25B8", ip, null);
            b.Tag = new SubmenuInfo(ip, fill);
            // Opens on hover like a normal submenu (see TrackHover); clicking also works.
            b.MouseEnter += delegate
            {
                if (subMenu == null || !subMenu.Visible) OpenSubmenu(b, ip, fill);
            };
            b.Click += delegate { OpenSubmenu(b, ip, fill); };
            return b;
        }

        class SubmenuInfo
        {
            public readonly string Ip;
            public readonly Action<ToolStripItemCollection, string> Fill;
            public SubmenuInfo(string ip, Action<ToolStripItemCollection, string> fill)
            {
                Ip = ip;
                Fill = fill;
            }
        }

        // While a submenu is open Windows sends mouse movement to it, so the
        // popup's own buttons never hear the mouse arrive. Track it here instead:
        // resting on another submenu button switches to it, resting on an
        // ordinary option closes the submenu. The short delay lets the mouse cut
        // diagonally across other buttons on its way into an open submenu.
        Button hoverButton;
        int hoverSince;
        const int SwitchDelayMs = 250;

        void TrackHover(Point c)
        {
            if (subMenu == null || !subMenu.Visible)
            {
                hoverButton = null;
                return;
            }
            if (OverMenu(subMenu, c))
            {
                hoverButton = null;
                return;
            }

            Button over = null;
            foreach (Control ctl in table.Controls)
            {
                Button bt = ctl as Button;
                if (bt != null && bt.RectangleToScreen(bt.ClientRectangle).Contains(c))
                {
                    over = bt;
                    break;
                }
            }
            if (over == null || over == subMenuOwner)
            {
                hoverButton = null;
                return;
            }
            if (over != hoverButton)
            {
                hoverButton = over;
                hoverSince = Environment.TickCount;
                return;
            }
            if (unchecked(Environment.TickCount - hoverSince) < SwitchDelayMs) return;

            hoverButton = null;
            SubmenuInfo info = over.Tag as SubmenuInfo;
            if (info != null) OpenSubmenu(over, info.Ip, info.Fill);
            else subMenu.Close();
        }

        void OpenSubmenu(Button b, string ip, Action<ToolStripItemCollection, string> fill)
        {
            if (subMenu == null)
            {
                subMenu = new ContextMenuStrip();
                subMenu.ShowImageMargin = false;
            }
            if (subMenu.Visible)
            {
                if (subMenuOwner == b) return;
                subMenu.Close();
            }
            while (subMenu.Items.Count > 0)
            {
                ToolStripItem old = subMenu.Items[0];
                subMenu.Items.RemoveAt(0);
                old.Dispose();
            }
            fill(subMenu.Items, ip);
            subMenuOwner = b;
            subMenu.Show(b, new Point(b.Width, 0));
        }

        ToolStripMenuItem Cmd(string text, string ip, Action<string> action)
        {
            ToolStripMenuItem item = new ToolStripMenuItem(text);
            item.Click += delegate
            {
                HidePopup();
                action(ip);
            };
            return item;
        }

        ToolStripMenuItem Ps(string text, string ip, string title, string body, bool remote)
        {
            return Cmd(text, ip, delegate(string t) { Actions.RunPowerShell(title, t, body, remote); });
        }

        static ToolStripMenuItem MakeGroup(string text)
        {
            ToolStripMenuItem g = new ToolStripMenuItem(text);
            ToolStripDropDownMenu dd = g.DropDown as ToolStripDropDownMenu;
            if (dd != null) dd.ShowImageMargin = false;
            return g;
        }

        void FillPsTools(ToolStripItemCollection m, string ip)
        {
            m.Add(Cmd("PsExec - remote command prompt", ip, Actions.PsExecCmd));
            m.Add(Cmd("PsExec - ipconfig /all", ip, Actions.PsExecIpconfig));
            m.Add(Cmd("PsInfo - system information", ip, Actions.PsInfo));
            m.Add(Cmd("PsLoggedOn - who is logged on", ip, Actions.PsLoggedOn));
            m.Add(Cmd("PsList - running processes", ip, Actions.PsList));
            m.Add(Cmd("PsService - services", ip, Actions.PsService));
        }

        // Run on this PC, towards the target.
        void FillNetTests(ToolStripItemCollection m, string ip)
        {
            m.Add(Ps("Test a TCP port...   (Test-NetConnection -Port)", ip, "TCP port test", PsScripts.TcpPort, false));
            m.Add(Ps("Test common TCP ports", ip, "Common ports", PsScripts.CommonPorts, false));
            m.Add(new ToolStripSeparator());
            m.Add(Ps("Resolve-DnsName", ip, "Resolve-DnsName", PsScripts.Dns, false));
            m.Add(Ps("Resolve-DnsName -Type A", ip, "Resolve-DnsName A", PsScripts.DnsA, false));
            m.Add(Ps("Resolve-DnsName -Server...", ip, "Resolve-DnsName via server", PsScripts.DnsServer, false));
            m.Add(new ToolStripSeparator());
            m.Add(Ps("Connections from this PC and their process", ip, "Connections", PsScripts.Connections, false));
            m.Add(Ps("Route from this PC   (Find-NetRoute)", ip, "Route", PsScripts.Route, false));
            m.Add(Ps("ARP / neighbour entry   (Get-NetNeighbor)", ip, "Neighbour entry", PsScripts.Neighbor, false));
        }

        // Run on the target itself.
        void FillRemote(ToolStripItemCollection m, string ip)
        {
            ToolStripMenuItem net = MakeGroup("Network");
            net.DropDownItems.Add(Ps("IP configuration   (Get-NetIPConfiguration)", ip, "IP configuration", PsScripts.IpConfig, true));
            net.DropDownItems.Add(Ps("Network adapters   (Get-NetAdapter)", ip, "Network adapters", PsScripts.Adapters, true));
            net.DropDownItems.Add(Ps("NIC errors and discards   (Get-NetAdapterStatistics)", ip, "NIC statistics", PsScripts.NicStats, true));
            net.DropDownItems.Add(Ps("Routes   (Get-NetRoute)", ip, "Routes", PsScripts.Routes, true));
            net.DropDownItems.Add(Ps("ARP / neighbour cache   (Get-NetNeighbor)", ip, "Neighbour cache", PsScripts.Arp, true));
            net.DropDownItems.Add(new ToolStripSeparator());
            net.DropDownItems.Add(Ps("Listening ports and their process", ip, "Listening ports", PsScripts.Listening, true));
            net.DropDownItems.Add(Ps("Established connections and their process", ip, "Established connections", PsScripts.Established, true));
            net.DropDownItems.Add(new ToolStripSeparator());
            net.DropDownItems.Add(Ps("Firewall profiles   (Get-NetFirewallProfile)", ip, "Firewall profiles", PsScripts.FwProfiles, true));
            net.DropDownItems.Add(Ps("Firewall rules - enabled   (Get-NetFirewallRule)", ip, "Firewall rules", PsScripts.FwRules, true));
            m.Add(net);

            ToolStripMenuItem sys = MakeGroup("System");
            sys.DropDownItems.Add(Ps("OS details   (Get-ComputerInfo)", ip, "OS details", PsScripts.OsInfo, true));
            sys.DropDownItems.Add(Ps("Installed hotfixes   (Get-HotFix)", ip, "Hotfixes", PsScripts.Hotfixes, true));
            sys.DropDownItems.Add(Ps("Processes   (Get-Process)", ip, "Processes", PsScripts.Processes, true));
            sys.DropDownItems.Add(Ps("Services   (Get-Service)", ip, "Services", PsScripts.Services, true));
            sys.DropDownItems.Add(Ps("Automatic services that are not running", ip, "Stopped automatic services", PsScripts.StoppedAuto, true));
            sys.DropDownItems.Add(Ps("Event log errors and warnings, last 24 h   (Get-WinEvent)", ip, "Event log", PsScripts.Events, true));
            m.Add(sys);

            ToolStripMenuItem perf = MakeGroup("Performance and storage");
            perf.DropDownItems.Add(Ps("CPU, memory and disk latency   (Get-Counter)", ip, "Performance counters", PsScripts.Perf, true));
            perf.DropDownItems.Add(Ps("Disks, volumes and physical disks", ip, "Disks and volumes", PsScripts.Disks, true));
            perf.DropDownItems.Add(Ps("Storage health   (Get-StorageReliabilityCounter)", ip, "Storage health", PsScripts.StorageHealth, true));
            m.Add(perf);

            ToolStripMenuItem wsfc = MakeGroup("Failover cluster (WSFC)");
            wsfc.DropDownItems.Add(Ps("Cluster, quorum and roles   (Get-Cluster)", ip, "Cluster", PsScripts.Cluster, true));
            wsfc.DropDownItems.Add(Ps("Cluster nodes   (Get-ClusterNode)", ip, "Cluster nodes", PsScripts.ClusterNodes, true));
            wsfc.DropDownItems.Add(Ps("Cluster resources   (Get-ClusterResource)", ip, "Cluster resources", PsScripts.ClusterResources, true));
            m.Add(wsfc);
        }

        // Is the point over this dropdown or any submenu opened from it?
        static bool OverMenu(ToolStripDropDown dd, Point c)
        {
            if (dd == null || !dd.Visible) return false;
            Rectangle r = dd.Bounds;
            r.Inflate(24, 24);
            if (r.Contains(c)) return true;
            foreach (ToolStripItem it in dd.Items)
            {
                ToolStripMenuItem mi = it as ToolStripMenuItem;
                if (mi != null && mi.HasDropDownItems && OverMenu(mi.DropDown, c)) return true;
            }
            return false;
        }

        // Dismiss once the mouse has left both the IP and the popup.
        void CheckMouseAway()
        {
            if (!Visible) { watch.Stop(); return; }
            Point c = Cursor.Position;
            TrackHover(c);
            if (OverMenu(subMenu, c)) return;
            Rectangle r = Bounds;
            r.Inflate(24, 24);
            if (r.Contains(c)) return;
            int dx = c.X - anchor.X;
            int dy = c.Y - anchor.Y;
            if (dx * dx + dy * dy <= 40 * 40) return;
            HidePopup();
        }
    }

    // --------------------------------------------------------------- about

    // Edit these to change what the About window shows. Empty links are hidden.
    static class AppInfo
    {
        public const string Name = "CtrlIt";
        public const string Version = "1.0.0";
        public const string Author = "ctrlittools";
        public const string Website = "https://github.com/ctrlittools/CtrlIt";
        public const string Donate = "https://ko-fi.com/ctrlittools";
    }

    static class AppIcon
    {
        // The icon file is built into the program (see build.bat), so each
        // size uses its own hand-made image rather than a shrunk large one.
        public static Icon Load(Size size)
        {
            try
            {
                using (System.IO.Stream st = System.Reflection.Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream("ctrlit.ico"))
                {
                    if (st != null) return new Icon(st, size);
                }
            }
            catch (Exception) { }
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch (Exception) { return SystemIcons.Application; }
        }
    }

    class AboutForm : Form
    {
        public AboutForm()
        {
            Text = "About " + AppInfo.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = true;
            TopMost = true;
            StartPosition = FormStartPosition.CenterScreen;
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(14, 12, 14, 12);
            Icon = AppIcon.Load(new Size(32, 32));

            TableLayoutPanel main = new TableLayoutPanel();
            main.AutoSize = true;
            main.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            main.ColumnCount = 3;
            main.RowCount = 3;
            main.Location = new Point(Padding.Left, Padding.Top);
            Controls.Add(main);

            PictureBox pic = new PictureBox();
            int iconPx = LogicalToDevice(48);
            using (Icon big = AppIcon.Load(new Size(iconPx, iconPx))) pic.Image = big.ToBitmap();
            pic.SizeMode = PictureBoxSizeMode.AutoSize;
            pic.Margin = new Padding(0, 2, 14, 0);
            main.Controls.Add(pic, 0, 0);
            main.SetRowSpan(pic, 2);

            Label title = new Label();
            title.Text = AppInfo.Name + "   " + AppInfo.Version;
            title.Font = new Font(Font.FontFamily, Font.SizeInPoints * 1.35f, FontStyle.Bold);
            title.AutoSize = true;
            title.Margin = new Padding(0, 2, 24, 2);
            main.Controls.Add(title, 1, 0);

            Label free = new Label();
            free.Text = "This program is free and open source (MIT licence)";
            free.AutoSize = true;
            free.Margin = new Padding(0, 2, 24, 2);
            main.Controls.Add(free, 1, 1);

            Button ok = new Button();
            ok.Text = "OK";
            ok.DialogResult = DialogResult.OK;
            ok.AutoSize = true;
            ok.MinimumSize = new Size(LogicalToDevice(80), 0);
            ok.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            ok.Click += delegate { Close(); };
            main.Controls.Add(ok, 2, 0);
            main.SetRowSpan(ok, 2);
            AcceptButton = ok;
            CancelButton = ok;

            TableLayoutPanel info = new TableLayoutPanel();
            info.AutoSize = true;
            info.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            info.ColumnCount = 2;
            info.Margin = new Padding(0, 16, 0, 0);
            main.Controls.Add(info, 0, 2);
            main.SetColumnSpan(info, 3);

            AddRow(info, "Written by", AppInfo.Author, null);
            if (AppInfo.Website.Length > 0)
            {
                string latest = AppInfo.Website.TrimEnd('/') + "/releases/latest";
                AddRow(info, "Check for the latest version at:", latest, latest);
                AddRow(info, "Source code and help:", AppInfo.Website, AppInfo.Website);
            }
            if (AppInfo.Donate.Length > 0)
                AddRow(info, "If it saves you time, support it at:", AppInfo.Donate, AppInfo.Donate);
        }

        int LogicalToDevice(int px)
        {
            using (Graphics g = CreateGraphics()) return (int)Math.Round(px * g.DpiX / 96f);
        }

        static void AddRow(TableLayoutPanel t, string caption, string text, string url)
        {
            int row = t.RowCount;
            t.RowCount = row + 1;

            Label cap = new Label();
            cap.Text = caption;
            cap.AutoSize = true;
            cap.Anchor = AnchorStyles.Right;
            cap.Margin = new Padding(0, 3, 8, 3);
            t.Controls.Add(cap, 0, row);

            Control value;
            if (url == null)
            {
                Label l = new Label();
                l.Text = text;
                value = l;
            }
            else
            {
                LinkLabel link = new LinkLabel();
                link.Text = text;
                link.LinkClicked += delegate
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(url);
                        psi.UseShellExecute = true;
                        Process.Start(psi);
                    }
                    catch (Exception) { }
                };
                value = link;
            }
            value.AutoSize = true;
            value.Anchor = AnchorStyles.Left;
            value.Margin = new Padding(0, 3, 0, 3);
            t.Controls.Add(value, 1, row);
        }
    }

    // ----------------------------------------------------- tray + mouse watch

    class TrayContext : ApplicationContext
    {
        const int DwellMs = 450;     // how long the mouse must rest on the IP
        const int PollMs = 80;

        readonly IpPopup popup;
        readonly NotifyIcon tray;
        readonly Thread worker;
        volatile bool stopping;
        string ocrProblem;
        int ocrFailures;

        public TrayContext()
        {
            Settings.Load();

            popup = new IpPopup();
            IntPtr force = popup.Handle; // create the window so BeginInvoke and the hotkey work
            popup.HotkeyPressed += delegate { LookUpClipboard(); };

            ToolStripMenuItem enabled = new ToolStripMenuItem("Enabled");
            enabled.CheckOnClick = true;
            enabled.Checked = Settings.Enabled;
            enabled.CheckedChanged += delegate
            {
                Settings.Enabled = enabled.Checked;
                Settings.Save();
                if (!enabled.Checked) popup.HidePopup();
            };

            ToolStripMenuItem ctrl = new ToolStripMenuItem("Only while Ctrl is held");
            ctrl.CheckOnClick = true;
            ctrl.Checked = Settings.RequireCtrl;
            ctrl.CheckedChanged += delegate
            {
                Settings.RequireCtrl = ctrl.Checked;
                Settings.Save();
            };

#if OCR
            ToolStripMenuItem ocr = new ToolStripMenuItem("Read text from the screen when needed (OCR)");
            ocr.CheckOnClick = true;
            ocr.Checked = Settings.UseOcr;
            ocr.CheckedChanged += delegate
            {
                Settings.UseOcr = ocr.Checked;
                Settings.Save();
            };
#endif

            ToolStripMenuItem hostTap = new ToolStripMenuItem("Tap or hold Ctrl to look up the word under the mouse as a hostname");
            hostTap.CheckOnClick = true;
            hostTap.Checked = Settings.HostOnCtrl;
            hostTap.CheckedChanged += delegate
            {
                Settings.HostOnCtrl = hostTap.Checked;
                Settings.Save();
            };

            ToolStripMenuItem startup = new ToolStripMenuItem("Start with Windows");
            startup.CheckOnClick = true;
            startup.Checked = Settings.StartWithWindows;
            startup.CheckedChanged += delegate { Settings.StartWithWindows = startup.Checked; };

            ToolStripMenuItem clip = new ToolStripMenuItem("Look up IP or hostname on clipboard\tCtrl+Alt+I");
            clip.Click += delegate { LookUpClipboard(); };

            ToolStripMenuItem aboutItem = new ToolStripMenuItem("About " + AppInfo.Name);
            aboutItem.Click += delegate { ShowAbout(); };

            ToolStripMenuItem exit = new ToolStripMenuItem("Exit");
            exit.Click += delegate { Quit(); };

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add(enabled);
            menu.Items.Add(ctrl);
            menu.Items.Add(hostTap);
#if OCR
            menu.Items.Add(ocr);
#endif
            menu.Items.Add(startup);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(clip);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(aboutItem);
            menu.Items.Add(exit);

            tray = new NotifyIcon();
            tray.Icon = LoadTrayIcon();
            tray.Text = "CtrlIt - hover an IP, or tap Ctrl on a hostname";
            tray.ContextMenuStrip = menu;
            tray.Visible = true;

            KeyWatcher.Start();

            worker = new Thread(WatchMouse);
            worker.IsBackground = true;
            worker.Name = "CtrlIt mouse watcher";
            worker.Start();
        }

        // Background thread: wait for the mouse to come to rest (or for a tap
        // of Ctrl), then ask the window underneath what text is there. Kept off
        // the UI thread because a busy or hung application can be slow to answer.
        void WatchMouse()
        {
            Point last = Cursor.Position;
            int restStart = Environment.TickCount;
            bool handled = true;
            int seenTaps = KeyWatcher.Taps;

            while (!stopping)
            {
                Thread.Sleep(PollMs);
                try
                {
                    int taps = KeyWatcher.Taps;
                    if (taps != seenTaps)
                    {
                        seenTaps = taps;
                        if (Settings.Enabled && Settings.HostOnCtrl)
                        {
                            Point tp = Cursor.Position;
                            last = tp;
                            handled = true;
                            if (!popup.ContainsPoint(tp)) LookUpAt(tp, true);
                            continue;
                        }
                    }

                    Point p = Cursor.Position;
                    if (Math.Abs(p.X - last.X) > 2 || Math.Abs(p.Y - last.Y) > 2)
                    {
                        last = p;
                        restStart = Environment.TickCount;
                        handled = false;
                        continue;
                    }
                    if (handled || !Settings.Enabled) continue;
                    if (unchecked(Environment.TickCount - restStart) < DwellMs) continue;

                    // Not while dragging / selecting, and honour the Ctrl option.
                    if (Native.IsDown(Native.VK_LBUTTON) || Native.IsDown(Native.VK_RBUTTON) ||
                        Native.IsDown(Native.VK_MBUTTON)) continue;
                    if (Settings.RequireCtrl && !Native.IsDown(Native.VK_CONTROL)) continue;

                    handled = true;
                    if (popup.ContainsPoint(p)) continue;
                    LookUpAt(p, false);
                }
                catch (Exception) { }
            }
        }

        // Find an IP under the point - or, when allowHost, any word to treat as
        // a host name - and show the popup for it.
        void LookUpAt(Point p, bool allowHost)
        {
            List<string> found = null;
            bool isHost = false;

            try { found = Detector.Detect(p, false); }
            catch (Exception) { }

            if (found == null && allowHost)
            {
                try
                {
                    found = Detector.Detect(p, true);
                    if (found != null) isHost = true;
                }
                catch (Exception) { }
            }

#if OCR
            if (found == null && Settings.UseOcr && ocrProblem == null)
            {
                try
                {
                    bool ocrHost;
                    string seen = ScreenReader.Detect(p, allowHost, out ocrHost);
                    if (seen != null)
                    {
                        found = new List<string>();
                        found.Add(seen);
                        isHost = ocrHost;
                    }
                    else if (ScreenReader.Problem != null) ocrProblem = ScreenReader.Problem;
                }
                catch (Exception ex)
                {
                    // A one-off failure is ignored; repeated ones switch it off.
                    if (++ocrFailures >= 3) ocrProblem = ex.GetType().Name + ": " + ex.Message;
                }
                if (ocrProblem != null)
                {
                    string why = ocrProblem;
                    popup.BeginInvoke((MethodInvoker)delegate
                    {
                        tray.ShowBalloonTip(8000, "CtrlIt - screen reading is off", why, ToolTipIcon.Warning);
                    });
                }
            }
#endif
            if (found == null || found.Count == 0) return;

            // Ignore the result if the mouse moved on while we were asking.
            Point now = Cursor.Position;
            if (Math.Abs(now.X - p.X) > 6 || Math.Abs(now.Y - p.Y) > 6) return;

            List<string> show = found;
            bool host = isHost;
            Point at = p;
            popup.BeginInvoke((MethodInvoker)delegate { popup.ShowFor(show, host, at); });
        }

        void LookUpClipboard()
        {
            string text = null;
            try { if (Clipboard.ContainsText()) text = Clipboard.GetText(); }
            catch (Exception) { }

            List<string> ips = new List<string>();
            bool isHost = false;
            if (text != null && text.Length <= 20000)
            {
                List<IpMatch> found = IpFinder.FindAll(text);
                for (int i = 0; i < found.Count && ips.Count < 4; i++)
                {
                    if (!ips.Contains(found[i].Value)) ips.Add(found[i].Value);
                }
                if (ips.Count == 0)
                {
                    string h = HostName.Whole(text);
                    if (h != null)
                    {
                        ips.Add(h);
                        isHost = true;
                    }
                }
            }

            if (ips.Count == 0)
            {
                tray.ShowBalloonTip(2500, "CtrlIt", "No IP address or host name found on the clipboard.", ToolTipIcon.Info);
                return;
            }
            popup.ShowFor(ips, isHost, Cursor.Position);
        }

        void Quit()
        {
            if (about != null && !about.IsDisposed) about.Close();
            stopping = true;
            tray.Visible = false;
            tray.Dispose();
            popup.Close();
            ExitThread();
        }

        static Icon LoadTrayIcon()
        {
            return AppIcon.Load(SystemInformation.SmallIconSize);
        }

        AboutForm about;

        void ShowAbout()
        {
            if (about == null || about.IsDisposed) about = new AboutForm();
            about.Show();
            about.Activate();
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            bool first;
            Mutex single = new Mutex(true, "CtrlIt_SingleInstance_7c1f", out first);
            if (!first) return;

            Native.EnableDpiAwareness();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TrayContext());
            GC.KeepAlive(single);
        }
    }
}
