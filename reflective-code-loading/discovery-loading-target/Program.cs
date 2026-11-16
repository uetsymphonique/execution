using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace WNetHelper
{
    class Program
    {
        static string OutputFile = null;
        static TextWriter Out = Console.Out;

        static void RunLocal()
        {
            SystemProfile.Run();
            SessionInfo.Run();
            ProcessCounter.Run();
            ServiceRegistry.Run();
            GroupMembership.Run();
            PathEnumerator.Run();
        }

        static void Main(string[] args)
        {
            try
            {
                var argList = new List<string>();
                foreach (string a in args)
                {
                    if (a == "-v" || a == "/v")
                    {
                        Diag.Verbose = true;
                        PerfCounter.Verbose = true;
                    }
                    else if ((a == "-o" || a == "/o") && argList.Count == 0)
                    {
                        OutputFile = Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                            "wnet-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".log");
                    }
                    else
                        argList.Add(a);
                }

                if (OutputFile == null)
                    OutputFile = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "wnet-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".log");

                using (var sw = new StreamWriter(OutputFile, false, Encoding.UTF8))
                {
                    Console.SetOut(sw);
                    RunLocal();
                    sw.Flush();
                }

                Console.SetOut(Out);
                Console.WriteLine("[+] Output written to " + OutputFile);
            }
            catch (Exception ex)
            {
                Console.SetOut(Out);
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}
