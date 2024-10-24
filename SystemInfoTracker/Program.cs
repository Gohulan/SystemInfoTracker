using System;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Diagnostics;
using System.Management;
using System.Reflection;
using System.Linq;


class Program
{
    static void Main()
    {
        // Folder and file paths
        string folderPath = @"C:\Systeminfo";
        string filePath = Path.Combine(folderPath, "sysinfo.txt");

        // Check if directory exists, if not create it
        if (!Directory.Exists(folderPath))
        {
            Directory.CreateDirectory(folderPath);
        }

        // Collecting system information
        string computerName = Environment.MachineName;
        string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
        string userName = Environment.UserName;
        string osVersion = Environment.OSVersion.ToString();
        string timeStamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");

        string ipAddress = GetLocalIPAddress();
        string publicIpAddress = GetPublicIPAddress();
        string macAddress = GetMacAddress();
        string ipconfigOutput = RunIpConfigCommand();
        string computerSerialNo = GetComputerSerialNumber();
        string baseBoardSerialNo = GetBaseBoardSerialNumber();
        string computerModel = GetComputerModel();




        string appVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        // Building the content to write to the file
        string content = $"Timestamp: {timeStamp}\n" +
                         $"Computer Name: {computerName}\n" +
                         $"Domain Name: {domainName}\n" +
                         $"User Name: {userName}\n" +
                         $"OS Version: {osVersion}\n" +
                         $"IP Address: {ipAddress}\n" +
                         $"Public IP Address: {publicIpAddress}\n" +
                         $"MAC Address: {macAddress}\n" +                        
                         $"App Version: {appVersion}\n" +
                         $"User Privileges (Admin): {isAdmin}\n" +
                         $"Detailed Network Info: {ipconfigOutput}\n" +
                         $"Computer Serial Info: {computerSerialNo}\n" +
                         $"Computer Baseboard Info: {baseBoardSerialNo}\n"+
                         $"Computer Model Info: {computerModel}\n"

;

        // Write the content to the file
        File.WriteAllText(filePath, content);

        Console.WriteLine("System information captured and saved to sysinfo.txt");
    }

    // Method to get local IP Address
    static string GetLocalIPAddress()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return ip.ToString();
            }
        }
        return "Local IP Address Not Found!";
    }

    // Method to get public IP Address
    static string GetPublicIPAddress()
    {
        try
        {
            using (var webClient = new WebClient())
            {
                string publicIP = webClient.DownloadString("https://api.ipify.org");
                return publicIP.Trim();
            }
        }
        catch
        {
            return "Public IP Address Not Found!";
        }
    }

    // Method to get MAC Address
    static string GetMacAddress()
    {
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var netInterface in networkInterfaces)
        {
            if (netInterface.OperationalStatus == OperationalStatus.Up)
            {
                return BitConverter.ToString(netInterface.GetPhysicalAddress().GetAddressBytes());
            }
        }
        return "MAC Address Not Found!";
    }

    private static string RunIpConfigCommand()
    {
        try
        {
            Process process = new Process();
            process.StartInfo.FileName = "ipconfig";
            process.StartInfo.Arguments = "/all";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return result;
        }
        catch (Exception ex)
        {
            return "Failed to run ipconfig: " + ex.Message;
        }
    }
    private static string GetComputerModel()
    {
        try
        {
            Process process = new Process();
            process.StartInfo.FileName = "wmic";
            process.StartInfo.Arguments = "csproduct get name";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string resultComputerSerialNo = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return resultComputerSerialNo;
        }
        catch (Exception ex)
        {
            return "Failed to run ipconfig: " + ex.Message;
        }
    }

    private static string GetComputerSerialNumber()
    {
        try
        {
            Process process = new Process();
            process.StartInfo.FileName = "wmic";
            process.StartInfo.Arguments = "bios get serialnumber";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string resultComputerSerialNo = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return resultComputerSerialNo;
        }
        catch (Exception ex)
        {
            return "Failed to run ipconfig: " + ex.Message;
        }
    }

    private static string GetBaseBoardSerialNumber()
    {
        try
        {
            Process process = new Process();
            process.StartInfo.FileName = "wmic";
            process.StartInfo.Arguments = "baseboard get product,serialnumber";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();

            string resultComputerSerialNo = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return resultComputerSerialNo;
        }
        catch (Exception ex)
        {
            return "Failed to run ipconfig: " + ex.Message;
        }
    }




}
