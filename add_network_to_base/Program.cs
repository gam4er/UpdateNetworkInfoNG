using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using MySql.Data.MySqlClient;
using System.Data.SqlClient;
using System.Net;
using System.Diagnostics;
using LukeSkywalker.IPNetwork;
using System.Net.Sockets;
using System.Threading.Tasks;


namespace add_network_to_base
{
    class Program
    {

        public static string connStr = @"Data Source=vn-cp-endpoint;Initial Catalog=CP_log;Integrated Security=True";

        public struct NetInfo
        {
            public string Net;
            public string Descr;
            public uint StartIP;
            public uint EndIP;

            public NetInfo(string tmpNet, string tmpDescr, uint SIP, uint EIP)
            {
                Net = tmpNet;
                Descr = tmpDescr;
                StartIP = SIP;
                EndIP = EIP;
            }
        }

        public struct IPandNet
        {
            public string IP;
            public NetInfo NI;

            public IPandNet(string tmpIP, NetInfo tmpNI)
            {
                IP = tmpIP;
                NI = tmpNI;
            }
        }

        public static uint IP2Int(string IPNumber)
        {
            uint ip = 0;
            string[] elements = IPNumber.Split(new Char[] { '.' });
            if (elements.Length == 4)
            {
                ip = Convert.ToUInt32(elements[0]) << 24;
                ip += Convert.ToUInt32(elements[1]) << 16;
                ip += Convert.ToUInt32(elements[2]) << 8;
                ip += Convert.ToUInt32(elements[3]);
            }
            return ip;
        }

        static void Network2IpRange(string sNetwork, out uint startIP, out uint endIP)
        {
            uint ip,		/* ip address */
                mask,		/* subnet mask */
                broadcast,	/* Broadcast address */
                network;	/* Network address */
                //usableIps;

            int bits;

            string[] elements = sNetwork.Split(new Char[] { '\\', '/' });



            ip = IP2Int(elements[0]);

            if (elements[1] == "32")
            {
                startIP = endIP = ip;
                return;
            }

            bits = Convert.ToInt32(elements[1]);

            mask = ~(0xffffffff >> bits);

            network = ip & mask;
            broadcast = network + ~mask;

            //usableIps = (bits > 30) ? 0 : (broadcast - network - 1);
                        
            startIP = network;
            endIP = broadcast;
            
        }
        
        public static List<NetInfo> GetNets()
        {
            MySqlConnection connection = new MySqlConnection("SERVER=10.46.48.180;" +
                                                 "DATABASE=ipdb;" +
                                                 "UID=reader;" +
                                                 "PASSWORD=reader;");

            MySqlConnection connectionRN = new MySqlConnection("SERVER=10.19.2.2;" +
                                                 "DATABASE=ipdb;" +
                                                 "UID=amrodchenko;" +
                                                 "PASSWORD=amr3588;");

            List<NetInfo> AllNets = new List<NetInfo>();

            try
            {
                connection.Open();

                MySqlCommand CmdReadNet = new MySqlCommand(
                    "SELECT CONCAT(CONVERT(INET_NTOA(ip) USING utf8), '/', CONVERT(prefix USING utf8)), descr FROM ipdb_sp.ipdb WHERE (descr is not NULL) AND (prefix <> 32) AND (ip > 0) order by prefix desc;", connection);
                CmdReadNet.CommandTimeout = 120;

                MySqlDataReader dataReader = CmdReadNet.ExecuteReader();


                for (int i = 0; dataReader.Read(); i++)
                {
                    string tmpNet = dataReader.GetString(0).Trim();
                    string tmpDescr = dataReader.GetString(1).Trim();
                    uint startIP = 0, endIP = 0;
                    Network2IpRange(tmpNet, out startIP, out endIP);
                    NetInfo tmpItem = new NetInfo(tmpNet, tmpDescr, startIP, endIP);
                    AllNets.Add(tmpItem);
                }

                dataReader.Close();
                dataReader.Dispose();

                connection.Close();
                connection.Dispose();

            }
            catch (MySqlException ex)
            {
                Console.WriteLine(ex);
            }


            try
            {
                connectionRN.Open();

                MySqlCommand CmdReadNet = new MySqlCommand(
                    "SELECT CONCAT(CONVERT(INET_NTOA(ip) USING utf8), '/', CONVERT(prefix USING utf8)), descr \n" +
                    "FROM ipdb.ipdb \n" +
                    "WHERE (descr is not NULL) AND (prefix <> 32) AND NOT (\n" +
                    "\t(ip BETWEEN INET_ATON('10.32.2.0') AND INET_ATON('10.32.2.255')) OR\n" +
                    "\t(ip BETWEEN INET_ATON('10.44.0.0') AND INET_ATON('10.47.255.255')) OR\n" +
                    "\t(ip BETWEEN INET_ATON('10.121.0.0') AND INET_ATON('10.121.255.255')) OR\n" +
                    "\t(ip BETWEEN INET_ATON('10.223.0.0') AND INET_ATON('10.223.255.255')) OR\n" + 
                    "\t(ip BETWEEN INET_ATON('10.252.0.0') AND INET_ATON('10.252.255.255')) OR\n" +
                    "\t(ip BETWEEN INET_ATON('109.236.254.0') AND INET_ATON('109.236.255.255')) OR\n" +
                    "\t(ip = INET_ATON('0.0.0.0'))\n" + 
                    ")" + 
                    "order by prefix desc;", connectionRN);
                CmdReadNet.CommandTimeout = 120;

                MySqlDataReader dataReader = CmdReadNet.ExecuteReader();


                for (int i = 0; dataReader.Read(); i++)
                {
                    string tmpNet = dataReader.GetString(0).Trim();
                    string tmpDescr = dataReader.GetString(1).Trim();
                    uint startIP = 0, endIP = 0;
                    Network2IpRange(tmpNet, out startIP, out endIP);
                    NetInfo tmpItem = new NetInfo(tmpNet, tmpDescr, startIP, endIP);
                    AllNets.Add(tmpItem);
                }

                dataReader.Close();
                dataReader.Dispose();

                connection.Close();
                connection.Dispose();

            }
            catch (MySqlException ex)
            {
                Console.WriteLine(ex);
            }

            List<NetInfo> sortedList = (from elem in AllNets
                             orderby (elem.EndIP - elem.StartIP)
                             select elem).ToList();


            return sortedList;
        }
        
        public static void GetRNNet(string IP, out string Net, out string Descr, List<NetInfo> AllNets)
        {                    

            for (int i = 0; i < AllNets.Count; i++)
            {
                if (IP2Int(IP) >= AllNets[i].StartIP && IP2Int(IP) <= AllNets[i].EndIP)
                {
                    Net = AllNets[i].Net;
                    Descr = AllNets[i].Descr;
                    return;
                }
            }
            Net = "10.0.0.0/8";
            Descr = "Подсеть Росненфть";

        }

        public static void GetNet(string IP, out string NetDescr, out string NetAndMask, List<NetInfo> AllNets)
        {

            if (IP.StartsWith("172.16.") || IP.StartsWith("172.16.") || IP.StartsWith("172.17.") || IP.StartsWith("172.18.") ||
                IP.StartsWith("172.19.") || IP.StartsWith("172.20.") || IP.StartsWith("172.21.") || IP.StartsWith("172.22.") || 
                IP.StartsWith("172.23.") || IP.StartsWith("172.24.") || IP.StartsWith("172.25.") || IP.StartsWith("172.26.") ||
                IP.StartsWith("172.27.") || IP.StartsWith("172.28.") || IP.StartsWith("172.29.") || IP.StartsWith("172.30.") || IP.StartsWith("172.31."))
            {
                NetAndMask = "172.16.0.0/12";
                NetDescr = "Серая сеть";
                return;
            }
            if (IP.StartsWith("192.168."))
            {
                NetDescr = "Серая сеть";
                NetAndMask = "192.168.0.0/16";
                return;
            }

            if (IP.StartsWith("10."))
            {
                GetRNNet(IP, out NetAndMask, out NetDescr, AllNets);
                return;
            }

            /*
             * Это хуиз через проксю 
             */

            GetPublicIP(IP, out NetAndMask, out NetDescr);

        }

        public static int Update(string NetWork, string NetDescr, string IP, SqlConnection Conn)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();

            NetWork = NetWork.Replace("'", " ").Replace("--", " ");
            NetDescr = NetDescr.Replace("'", " ").Replace("--", " ");

            int result = 0, updated = 0, current = 0;

            SqlCommand UpdateData = new SqlCommand(
                "UPDATE TOP (100000)[CP_log].[dbo].[" + TableName +"]\n" + 
                "SET [SrcDescr] = '" + NetDescr + "',\n" +
                "[SrcNet] = '" + NetWork + "'\n" +
                "WHERE [SrcInInt] = dbo.ipStringToInt('" + IP.ToString() + "')" + "\n" +
                "      AND [SrcNet] IS NULL", Conn);

            Console.WriteLine("Обновляю информацию об конкретном IP источнике: {0}", IP);

            UpdateData.CommandTimeout = 20 * 60;

            try
            {
                do
                {
                    current = UpdateData.ExecuteNonQuery();
                    updated += current;
                    Console.WriteLine("Было обновлено {0} записей источника", updated);
                }
                while (current == 100000);
            }
            catch (SqlException sqlEx)
            {
                Console.WriteLine(sqlEx);
                Console.WriteLine("Всего обновлено {0} записей  для IP источника {1} и произошла ошибка", updated, IP);
                return updated + result; 
            }
            catch (System.InvalidOperationException SysIn)
            {
                Console.WriteLine(SysIn);
                Console.WriteLine("Всего обновлено {0} записей  для IP источника {1} и произошла ошибка", updated, IP);
                return updated + result; 
            }

            Console.WriteLine("Всего обновлено {0} записей для источника {1} ", updated, IP.ToString());

            result = updated;
            updated = 0;
                        
            sw.Stop();
            Console.WriteLine("Заняло {0}", sw.Elapsed);
            sw.Restart();

            UpdateData.CommandText = UpdateData.CommandText.Replace("[SrcDescr]", "[DstDescr]").Replace("[SrcNet]", "[DstNet]").Replace("[SrcInInt]", "[DstInInt]");

            Console.WriteLine("Обновляю информацию об конкретном IP получателе: {0}", IP);

            try
            {
                do
                {
                    current = UpdateData.ExecuteNonQuery();
                    updated += current;
                    Console.WriteLine("Было обновлено {0} записей источника", updated);
                }
                while (current == 100000);
            }
            catch (SqlException sqlEx)
            {
                Console.WriteLine(sqlEx);
                Console.WriteLine("Всего обновлено {0} записей  для IP назначения {1} и произошла ошибка", updated, IP);
                return updated + result; 
            }
            catch (System.InvalidOperationException SysIn)
            {
                Console.WriteLine(SysIn);
                Console.WriteLine("Всего обновлено {0} записей  для IP назначения {1} и произошла ошибка", updated, IP);
                return updated + result; 
            }

            Console.WriteLine("Всего обновлено {0} записей для назначения {1} ", updated, IP.ToString());

            UpdateData.Dispose();
            result += updated;

            Console.WriteLine("Всего было обновлено {0} записей", result);
            
            sw.Stop();
            Console.WriteLine("Заняло {0}\n\n", sw.Elapsed);

            return result;
        }

        public static string IsItRightAnswer(string RawResult, string WhoisServer, string IP)
        {
            /*
             * Ошибочки словим
             * «0.0.0.0 — 255.255.255.255» или «0::/0» (для всех)
             * «network range is not allocated to apnic» (для APNIC)
             * «address block not managed by the ripe» или «does not operate any networks using» (для RIPE)
             * «afrinic whois server» или «ripe database query service» (для LACNIC)
             * «whois.arin.net» или «allocated to arin», при условии, что упоминается другой региональный сервер, чем к которому был запрос
             */

            if (RawResult.Contains("0.0.0.0 — 255.255.255.255"))
                return "";
            if (RawResult.Contains("network range is not allocated to apnic") && WhoisServer == "whois.apnic.net")
                return "";
            if (RawResult.Contains("address block not managed by the ripe") && WhoisServer == "whois.ripe.net")
                return "";
            if (RawResult.Contains("does not operate any networks using") && WhoisServer == "whois.ripe.net")
                return "";
            if (RawResult.Contains("afrinic whois server") && WhoisServer == "whois.lacnic.net")
                return "";
            if (RawResult.Contains("ripe database query service") && WhoisServer == "whois.lacnic.net")
                return "";
            if (RawResult.Contains("whois.arin.net") && WhoisServer != "whois.arin.net")
                return "";
            if (RawResult.Contains("allocated to arin") && WhoisServer != "whois.arin.net")
                return "";

            string result = "";

            Regex regex = new Regex(@"(%(.)*?$)|(#(.)*?$)", RegexOptions.Compiled | RegexOptions.Multiline);
            result = regex.Replace(RawResult, "");

            Regex RemEmptyLines = new Regex(@"[\r\n]+|[\r]+|[\n]+", RegexOptions.Compiled | RegexOptions.Multiline);
            result = RemEmptyLines.Replace(result, "\n");

            if (result.Length < 20)
                return "";

            return result;
        }

        public static string AskAllServ(string QueryString)
        {
            List<string> WhoisServers = new List<string>();

            WhoisServers.Add("whois.arin.net");
            WhoisServers.Add("whois.iana.org");
            WhoisServers.Add("whois.apnic.net");
            WhoisServers.Add("whois.ripe.net");
            WhoisServers.Add("whois.afrinic.net");
            WhoisServers.Add("whois.lacnic.net");

            /*
             * whois.arin.net (ARIN, Северная Америка)
             * whois.apnic.net (APNIC, Азия и Тихоокеанский регион)
             * whois.ripe.net (RIPE, Европа и Ближний Восток)
             * whois.afrinic.net (AfriNIC, Африка)
             * whois.lacnic.net (LACNIC, Латинская Америка)
             * whois.iana.org
             */

            foreach (string tldWhoisServer in WhoisServers)
            {
                string result = GetWhoisInformation(tldWhoisServer, QueryString);


                string[] split = { "# start", "# end" };

                List<string> subresults = result.Split(split, StringSplitOptions.RemoveEmptyEntries).ToList();

                for (int i = 0; i < subresults.Count; i++)
                {
                    subresults[i] = IsItRightAnswer(subresults[i], tldWhoisServer, QueryString);
                    if (subresults[i].Length < 20)
                    {
                        subresults.RemoveAt(i);
                        i--;
                    }
                }

                string trimmedResult = "";

                if (subresults.Count == 1)
                {
                    trimmedResult = subresults[0];
                }
                else
                {
                    if (subresults.Count == 0)
                    {
                        continue;
                    }

                    IPNetwork[] NewTypeNet = new IPNetwork[subresults.Count];

                    for (int i = 0; i < subresults.Count; i++)
                    {
                        string rawsubnetstring = "";

                        int first = subresults[i].IndexOf("inetnum:") + 8;
                        int last = subresults[i].IndexOf("\n", first);

                        if (first == 7)
                        {
                            first = subresults[i].IndexOf("NetRange:") + 9;
                            last = subresults[i].IndexOf("\n", first);
                            if (first == 8)
                                rawsubnetstring = "0.0.0.0 - 255.255.255.255";
                            else
                                rawsubnetstring = subresults[i].Substring(first, last - first).Trim();
                        }
                        else
                            rawsubnetstring = subresults[i].Substring(first, last - first).Trim();

                        string[] splitNet = { " - ", " ", "-" };
                        string[] subnets = rawsubnetstring.Split(splitNet, StringSplitOptions.RemoveEmptyEntries);

                        IPNetwork[] NewTypeSubnets = new IPNetwork[subnets.Length];

                        for (int j = 0; j < subnets.Length; j++)
                        {
                            try
                            {
                                NewTypeSubnets[j] = IPNetwork.Parse(subnets[j].Trim() + "/32");
                            }
                            catch (Exception ex)
                            {
                                NewTypeSubnets[j] = IPNetwork.Parse("0.0.0.0/0");
                                Console.WriteLine(ex);
                            }
                        }
                        NewTypeNet[i] = IPNetwork.WideSubnet(NewTypeSubnets);
                    }

                    trimmedResult = subresults[0];
                    for (int i = 1; i < subresults.Count; i++)
                        if (NewTypeNet[i].Usable < NewTypeNet[i - 1].Usable)
                            trimmedResult = subresults[i];
                }

                string refserv = returnReferral(trimmedResult, tldWhoisServer);
                if (refserv != "")
                {
                    string tmptrimmedResult = GetWhoisInformation(refserv, QueryString);
                    tmptrimmedResult = IsItRightAnswer(tmptrimmedResult, refserv, QueryString);
                    if (tmptrimmedResult.Length < 40)
                        return trimmedResult;
                    return tmptrimmedResult;
                }
                else
                    return trimmedResult;

            }
            return "";
        }

        public static string returnReferral(string response, string server)
        {
            if (server == "whois.arin.net" && response.Contains("ReferralServer:"))
            {

                int first = response.IndexOf("ReferralServer:") + 15;
                int last = response.IndexOf("\n", first);

                string result = response.Substring(first, last - first);
                if (result.Contains("rwhois://"))
                    return "";
                result = result.Trim().Replace("whois://", "").Replace(":43", "");
                return result;

            }

            if (server == "whois.iana.org" && response.Contains("refer:"))
            {
                int first = response.IndexOf("refer:") + 6;
                int last = response.IndexOf("\n", first);

                string result = response.Substring(first, last - first).Trim();

                if (result.Contains("rwhois://"))
                    return "";

                result = result.Trim().Replace("whois://", "").Replace(":43", "");

                return result;
            }

            if (response.Contains("whois:"))
            {
                int first = response.IndexOf("whois:") + 6;
                int last = response.IndexOf("\n", first);

                string result = response.Substring(first, last - first).Trim();

                if (result.Contains("rwhois://"))
                    return "";

                first = result.IndexOf("/");
                if (first > 0)
                    result = result.Substring(0, first);

                first = result.IndexOf(":");
                if (first > 0)
                    result = result.Substring(0, first);

                return result;
            }

            return "";

        }

        static string GetWhoisInformation(string whoisServer, string url)
        {
            if (whoisServer == "whois.arin.net")
                url = "n + " + url;
            
            StringBuilder stringBuilderResult = new StringBuilder();

            try
            {
                
                TcpClient tcpClinetWhois = new TcpClient(whoisServer, 43);
                NetworkStream networkStreamWhois = tcpClinetWhois.GetStream();
                BufferedStream bufferedStreamWhois = new BufferedStream(networkStreamWhois);
                StreamWriter streamWriter = new StreamWriter(bufferedStreamWhois);

                streamWriter.WriteLine(url);
                streamWriter.Flush();

                StreamReader streamReaderReceive = new StreamReader(bufferedStreamWhois);

                while (!streamReaderReceive.EndOfStream)
                    stringBuilderResult.AppendLine(streamReaderReceive.ReadLine());

                streamReaderReceive.Close();
                streamWriter.Close();
                bufferedStreamWhois.Close();
                networkStreamWhois.Close();
                tcpClinetWhois.Close();

                return stringBuilderResult.ToString();
            }
            catch
            {
                return stringBuilderResult.ToString();
            }
        }
        
        public static void GetPublicIP(string IP, out string net, out string company)
        {

            string response = AskAllServ(IP);
            string rawsubnetstring = "";

            int first = response.IndexOf("inetnum:") + 8;
            int last = response.IndexOf("\n", first);

            if (first == 7)
            {
                first = response.IndexOf("NetRange:") + 9;
                last = response.IndexOf("\n", first);
                if (first == 8)
                    rawsubnetstring = "0.0.0.0 - 255.255.255.255";
                else
                    rawsubnetstring = response.Substring(first, last - first).Trim();
            }
            else
                rawsubnetstring = response.Substring(first, last - first).Trim();

            string[] split = { " - ", " ", "-" };
            string[] subnets = rawsubnetstring.Split(split, StringSplitOptions.RemoveEmptyEntries);
                
            IPNetwork[] NewTypeSubnets = new IPNetwork[subnets.Length];

            for (int i = 0; i < subnets.Length; i++)
            {
                try
                {
                    NewTypeSubnets[i] = IPNetwork.Parse(subnets[i].Trim() + "/32");
                }
                catch (Exception ex)
                {
                    NewTypeSubnets[i] = IPNetwork.Parse("0.0.0.0/0");
                    Console.WriteLine(ex);
                }
            }
            IPNetwork NewTypeNet = IPNetwork.WideSubnet(NewTypeSubnets);
            net = NewTypeNet.ToString();
                
            first = response.IndexOf("OrgName:") + 8;
            last = response.IndexOf("\n", first);
            if (first == 7)
            {
                first = response.IndexOf("org-name:") + 9;
                last = response.IndexOf("\n", first);
                if (first == 8)
                {
                    first = response.IndexOf("organisation:") + 13;
                    last = response.IndexOf("\n", first);
                    if (first == 12)
                    {
                        first = response.IndexOf("Organization:") + 13;
                        last = response.IndexOf("\n", first);
                        if (first == 12)
                        {
                            first = response.IndexOf("Name:") + 5;
                            last = response.IndexOf("\n", first);
                            if (first == 4)
                            {
                                first = response.IndexOf("role:") + 5;
                                last = response.IndexOf("\n", first);
                                if (first == 4)
                                {
                                    first = response.IndexOf("descr:") + 6;
                                    last = response.IndexOf("\n", first);
                                    if (first == 5)
                                    {
                                        first = response.IndexOf("person:") + 7;
                                        last = response.IndexOf("\n", first);
                                        if (first == 6)
                                        {
                                            first = response.IndexOf("address:") + 8;
                                            last = response.IndexOf("\n", first);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            company = response.Substring(first, last - first).Trim();

            if (company.Length > 255)
                company = company.Remove(254);

            return;
        }

        public static List<string> GetUnknownIP(SqlConnection Conn)
        {
            List<string> tmpIP = new List<string>();

            SqlCommand CmdReadIP = new SqlCommand(
                "SELECT TOP 200 [dbo].[ipIntToString]([SrcInInt]), count(*) AS [Count] \n" + 
                "FROM [CP_log].[dbo].[" + TableName +"] \n" +
                "Where [SrcNet] is NULL \n" +
                "group by [SrcInInt] \n" + 
                "order by 2 desc", Conn);

            CmdReadIP.CommandTimeout = 60*20;

            Conn.Close();
            Conn.Open();

            SqlDataReader dr;

            try
            {
                dr = CmdReadIP.ExecuteReader();

                while (dr.Read())
                    tmpIP.Add(dr.GetValue(0).ToString().Trim());

                CmdReadIP.CommandText = CmdReadIP.CommandText.Replace("[SrcNet]", "[DstNet]").Replace("[SrcInInt]", "[DstInInt]");

                dr.Close();
                dr.Dispose();

                dr = CmdReadIP.ExecuteReader();
                while (dr.Read())
                    tmpIP.Add(dr.GetValue(0).ToString().Trim());

                dr.Close();
                dr.Dispose();

            }
            catch (SqlException sqlexc)
            {
                Console.WriteLine("Произошла ошибка выполнения запроса:\n{0}", sqlexc);                
                return tmpIP;
            }

            return tmpIP.Distinct().ToList();
    }

        public static bool PossibleToUpdateNet(string Net, List<NetInfo> AllNets)
        {
            UInt32 startIP = 0, endIP = 0;
            Network2IpRange(Net, out startIP, out endIP);

            if (Net.StartsWith("10."))
            {
                foreach (NetInfo tmpNet in AllNets)
                    if (startIP < tmpNet.StartIP && endIP > tmpNet.EndIP)
                        return false;
            }
            else
            {
                if ((endIP - startIP) > 32770)
                    return false;
            }

            return true;
        }

        public static int UpdateNet(string Net, string NetDescr, SqlConnection Conn)
        {
            UInt32 startIP = 0, endIP = 0;
            Network2IpRange(Net, out startIP, out endIP);

            Net = Net.Replace("'", " ").Replace("--", " ");
            NetDescr = NetDescr.Replace("'", " ").Replace("--", " ");

            int updated = 0, result = 0, current = 0;


            SqlCommand UpdateData = new SqlCommand("UPDATE TOP (100000) [CP_log].[dbo].[" + TableName +"]\n" +
                "\tSET [SrcDescr] = '" + NetDescr + "',\n" +
                "\t    [SrcNet] = '" + Net + "'\n" +
                "\tWHERE [SrcInInt] BETWEEN " + startIP.ToString() + " AND " + endIP.ToString() + "\n" +
                "\t      AND [SrcNet] IS NULL", Conn);

            Console.WriteLine("Обновляю информацию о сети источнике: {0} с описанием\n{1}", Net, NetDescr);
            UpdateData.CommandTimeout = 10 * 60;
            
            Stopwatch sw = new Stopwatch();
            sw.Start();

            try
            {
                do
                {
                    current = UpdateData.ExecuteNonQuery();
                    updated += current;
                    Console.WriteLine("Было обновлено  {0} записей по источнику", updated);
                }
                while (current == 100000);
            }
            catch (SqlException sqlEx)
            {
                Console.WriteLine(sqlEx);
                Console.WriteLine("Всего обновлено {0} записей по источнику для сети {1} и произошла ошибка", updated, Net);
                return updated + result; 
            }
            catch (System.InvalidOperationException SysIn)
            {
                Console.WriteLine(SysIn);
                Console.WriteLine("Всего обновлено {0} записей по источнику для сети {1} и произошла ошибка", updated, Net);
                return updated + result; 
            }

            Console.WriteLine("Всего обновлено {0} записей по источнику для сети {1}", updated, Net);

            result = updated;
            updated = 0;

            sw.Stop();
            Console.WriteLine("/---------Заняло {0}---------/", sw.Elapsed);
            sw.Restart();

            UpdateData.CommandText = UpdateData.CommandText.Replace("[SrcDescr]", "[DstDescr]").Replace("[SrcNet]", "[DstNet]").Replace("[SrcInInt]", "[DstInInt]");
            
            try
            {
                do
                {
                    current = UpdateData.ExecuteNonQuery();
                    updated += current;
                    Console.WriteLine("Было обновлено  {0} записей по назначению ", updated);
                }
                while (current == 100000);
            }
            catch (SqlException sqlEx)
            {
                Console.WriteLine(sqlEx);
                Console.WriteLine("Всего обновлено {0} записей по назначению для сети {1} и произошла ошибка", updated, Net);
                return updated + result; 
            }
            catch (System.InvalidOperationException SysIn)
            {
                Console.WriteLine(SysIn);
                Console.WriteLine("Всего обновлено {0} записей по назначению для сети {1} и произошла ошибка", updated, Net);
                return updated + result; 
            }

            Console.WriteLine("Всего обновлено {0} записей по назначению для сети {1}", updated+result, Net);

            sw.Stop();
            Console.WriteLine("/---------Заняло {0}---------/", sw.Elapsed);

            UpdateData.Dispose();

            return updated + result;

        }

        public static string TableName = "RNI";

        static void Main(string[] args)
        {

            System.IO.StreamWriter LogToFile = new System.IO.StreamWriter("Log.txt");
            LogToFile.AutoFlush = true;
            Console.SetOut(LogToFile);

            //string connStr = @"Data Source=;Initial Catalog=CP_log;Integrated Security=True";
            SqlConnection Conn = new SqlConnection(connStr);
            try { Conn.Open(); }
            catch (SqlException se) {
                Console.WriteLine("Ошибка подключения для чтения:{0}", se.Message);
                return; }

            Console.WriteLine("Соединение для чтения успешно произведено");

            if (args.Length == 1)
            {
                SqlCommand CmdReadIP = new SqlCommand("select [TABLE_NAME] from information_schema.tables", Conn);

                CmdReadIP.CommandTimeout = 60 * 20;
                SqlDataReader dr;

                try
                {
                    dr = CmdReadIP.ExecuteReader();
                    string ThisTable = "";
                    bool TableExsist = false;

                    while (dr.Read())
                    {
                        ThisTable = dr.GetValue(0).ToString().Trim().ToLower();
                        if (ThisTable == args[0].ToLower())
                        {
                            TableName = args[0].ToLower();
                            TableExsist = true;
                            break;
                        }
                        if (ThisTable == TableName)
                            TableExsist = true;
                    }
                    dr.Close();
                    dr.Dispose();
                    if (!TableExsist)
                    {
                        Console.WriteLine("Таблица {0} для обновления не существует", args[0]);
                        return;
                    }
                }
                catch (SqlException sqlexc)
                {
                    Console.WriteLine("Произошла ошибка выполнения запроса при проверке существования таблицы:\n{0}", sqlexc);
                    return;
                }
            }
            else
            {
                Console.WriteLine("Запустите с одним аргументом: именем обновляемой таблицы");
                return;
            }
            
            Console.WriteLine("Использую таблицу " + TableName);

            Int64 result = 0;
            
            List<string> IPlist = new List<string>();

            try
            {
                
                List<NetInfo> AllNets = GetNets();

                do
                {
                    IPlist = GetUnknownIP(Conn);
                    List<string> DistinctIP = IPlist.Distinct().ToList();
                    List<IPandNet> listIPandNet = new List<IPandNet>();

                    Parallel.For(0, DistinctIP.Count, (j, loopState) =>
                    {
                        Stopwatch sw = new Stopwatch();
                        sw.Start();
                        
                        string Network = "", NetDescr = "";

                        if (j >= DistinctIP.Count)
                            loopState.Break();

                        if (loopState.IsStopped)
                            loopState.Break();

                        GetNet(DistinctIP[j], out NetDescr, out Network, AllNets);
                        uint x = 0, y = 0;
                        Network2IpRange(Network, out x, out y);
                        NetInfo tmpNet = new NetInfo(Network, NetDescr, x, y);
                        IPandNet tmpIPNet = new IPandNet(DistinctIP[j], tmpNet);
                        listIPandNet.Add(tmpIPNet);

                    }
                    );

                    for (int i = 0 ; i < listIPandNet.Count ; i++)
                    {
                        if (PossibleToUpdateNet(listIPandNet[i].NI.Net, AllNets))
                        {
                            for (int j = 0 ; j < listIPandNet.Count ; j++)
                            {
                                if (((IP2Int(listIPandNet[i].IP) > listIPandNet[j].NI.StartIP) && (IP2Int(listIPandNet[i].IP) < listIPandNet[j].NI.EndIP)) && i != j)
                                {
                                    listIPandNet.RemoveAt(j);
                                    i--;
                                    break;
                                }
                            }
                        }
                    }

                    Console.WriteLine("\n-=Новый запрос=-\n");

                    int current = 0;

                    foreach (IPandNet IP in listIPandNet)
                    {
                        if (PossibleToUpdateNet(IP.NI.Net, AllNets))
                        {
                            current = UpdateNet(IP.NI.Net, IP.NI.Descr, Conn);
                            if (current >= 0)
                                result += current;
                            else
                            {
                                Console.WriteLine("\nПроизошла ошибка аварийный выход\n");
                                return;
                            }
                        }
                        else
                        {
                            current = Update(IP.NI.Net, IP.NI.Descr, IP.IP, Conn);
                            if (current >= 0)
                                result += current;
                            else
                            {
                                Console.WriteLine("\nПроизошла ошибка аварийный выход\n");
                                return;
                            }
                        }
                    }

                }
                while (IPlist.Count > 0);

            }
            catch (MySqlException ex)
            {
                switch (ex.Number)
                {
                    case 0:
                        Console.WriteLine("Cannot connect to server.  Contact administrator\n" + ex.ToString());
                        break;
                        
                    case 1045:
                        Console.WriteLine("Invalid username/password, please try again\n" + ex.ToString());
                        break;
                    default:
                        Console.WriteLine(ex);
                        break;
                }
                return;
            }

           

            Console.WriteLine("Обновил {0} строк",result);            
        }
    }
}
