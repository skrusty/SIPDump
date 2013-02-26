using LumiSoft.Net.SDP;
using LumiSoft.Net.SIP.Message;
using LumiSoft.Net.SIP.Stack;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace SIPDump
{

    public class Call
    {
        public enum PacketType
        {
            SIPDialog,
            RTP
        }
        public enum CallDirection {Caller, Callee};

        #region Public Properties
        public DateTime CallStarted { get; set; }
        public string CallID { get; set; }
        public bool SeenBYE { get; set; }
        public bool Confirmed { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public int CallerRTPPort { get; set; }
        public int CalleeRTPPort { get; set; }
        public IPAddress CallerIP { get; set; }
        public IPAddress CalleeIP { get; set; }

        public string CallerID { get; set; }
        public string CalleeID { get; set; }

        public List<UdpPacket> SIPMessages { get; set; }

        public CallDirection WhoHungUp { get; set; }
        #endregion

        #region Public Static Properties

        public static Dictionary<string, Call> Calls = new Dictionary<string, Call>(); 

        #endregion

        private CaptureFileWriterDevice captureFileWriter;
        //WaveFormat g726Format = new WaveFormat(8000, 32, 1);
        //WaveFileWriter wavWriter;

        public Call(string callID)
        {
            Console.WriteLine("Setup new call: " + callID);
            
            // Init collection of sip messages
            SIPMessages = new List<UdpPacket>();

            // Setup capture file
            captureFileWriter = new CaptureFileWriterDevice("Calls\\" + callID + ".pcap");

            // Setup properties
            this.CallID = callID;
            // Set call started date/time
            CallStarted = DateTime.Now;
        }

        #region Public Methods
        public void WritePacket(RawCapture raw, PacketType type)
        {
            captureFileWriter.Write(raw);
            //if (type == PacketType.SIPDialog)
            //{
            //    var packet = PacketDotNet.Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            //    var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet);

            //    SIPMessages.Add(udpPacket);
            //}
            //if (type == PacketType.RTP)
            //{
            //    if (wavWriter == null)
            //    {
            //        wavWriter = new WaveFileWriter("Calls\\" + CallID + ".wav", g726Format);
            //    }
            //    var packet = PacketDotNet.Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            //    var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet);
            //    wavWriter.Write(udpPacket.PayloadData, 0, udpPacket.PayloadData.Length);
            //}
            
        }

        public void CloseCall()
        {
            // Close capture file
            captureFileWriter.Close();

            // Create details file
            using (StreamWriter sr = new StreamWriter(File.OpenWrite("Calls\\" + CallID + ".txt")))
            {
                sr.WriteLine(string.Format("{0,-20}: {1}", "Call Started", CallStarted.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Callee", this.CalleeIP.ToString()));
                // sr.WriteLine(string.Format("{0,-20}: {1}", "Callee ID", this.CalleeID.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Caller", this.CallerIP.ToString()));
                // sr.WriteLine(string.Format("{0,-20}: {1}", "Caller ID", this.CallerID.ToString()));
                sr.WriteLine(string.Format("{0,-20}: {1}", "Hungup", this.WhoHungUp.ToString()));
            }



            //if (wavWriter != null)
            //{
            //    wavWriter.Flush();
            //    wavWriter.Close();
            //}
        }

        public void WriteAudioFile()
        {
            // WaveFormatEncoding.Adpcm
            

        }
        #endregion

        #region Static methods

        public static Call GetCallByRTPPort(int port) 
        {
            foreach (var c in Calls)
            {
                if (c.Value.CalleeRTPPort == port || c.Value.CallerRTPPort == port)
                    return c.Value;
            }
            return null;
        }

        #endregion
    }

    public class SIPDump
    {
        public class SIPMessage : SIP_Message
        {
            public SIPMessage(byte[] data)
            {
                this.InternalParse(data);
            }
        }

        public static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;
            string ver = SharpPcap.Version.VersionString;
            
            Console.WriteLine("SIPDump using: SharpPcap {0}", ver);
            Console.WriteLine();

            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;

            /*If no device exists, print error */
            if(devices.Count<1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }
            
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i=0;

            /* Scan the list printing every entry */
            foreach(var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            var device = devices[i];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += 
                new PacketArrivalEventHandler( device_OnPacketArrival );

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //tcpdump filter to capture only TCP/IP packets
            string filter = "ip and tcp";

            Console.WriteLine
                ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);

            // Check calls folder is there
            if (!Directory.Exists("Calls"))
                Directory.CreateDirectory("Calls");

            // Start capture 'INFINTE' number of packets
            device.Capture();

            // (Note: this line will never be called since
            //  we're capturing infinite number of packets
            device.Close();
        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            foreach (var call in Call.Calls)
            {
                call.Value.CloseCall();
            }
        }

        public static SIP_Message ParseSIPMessage(byte[] data)
        {
            try
            {
                return SIP_Request.Parse(data);
            }
            catch
            {
                try
                {
                    return SIP_Response.Parse(data);
                }
                catch
                {
                    return null;
                }
            }
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {           
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet);
            if (udpPacket != null)
            {                
                try
                {
                    // signalling packet
                    SIP_Message msg = ParseSIPMessage(udpPacket.PayloadData);
                    if(msg!=null && msg.CallID != null)
                    {
                        SDP_Message sdp = null;

                        try
                        {
                            sdp = SDP_Message.Parse(System.Text.ASCIIEncoding.Default.GetString(msg.Data));
                        }
                        catch { }

                        if (msg is SIP_Request && msg.CallID != null)
                        {
                            SIP_Request r = (SIP_Request)msg;                           

                            if (!Call.Calls.ContainsKey(r.CallID))
                            {
                                if (r.RequestLine.Method == "INVITE")
                                {
                                    Call.Calls.Add(r.CallID, new Call(r.CallID));
                                    Call.Calls[r.CallID].CallerIP = ((IpPacket)udpPacket.ParentPacket).SourceAddress;
                                    Call.Calls[r.CallID].CalleeIP = ((IpPacket)udpPacket.ParentPacket).DestinationAddress;
                                }
                                else
                                    return;     // Ignore this conversation
                            }
                            
                            // if this is an invite, do we have an audio rtp port defined?
                            if (r.RequestLine.Method == "INVITE")
                            {
                                if (sdp != null)
                                {
                                    foreach (var a in sdp.MediaDescriptions)
                                    {
                                        Console.Out.WriteLine(r.CallID + " - Got RTP Media Port: " + ((IpPacket)udpPacket.ParentPacket).SourceAddress + ":" + a.Port.ToString());
                                        if (Call.Calls[r.CallID].CallerIP.ToString() == ((IpPacket)udpPacket.ParentPacket).SourceAddress.ToString())
                                            Call.Calls[r.CallID].CallerRTPPort = a.Port;
                                        else
                                            Call.Calls[r.CallID].CalleeRTPPort = a.Port;
                                    }
                                }
                            }

                            if (r.RequestLine.Method == "BYE")
                            {
                                if (Call.Calls.ContainsKey(r.CallID))
                                {
                                    // Log bye was recevied
                                    Call.Calls[r.CallID].SeenBYE = true;

                                    // Now indicate who hung up
                                    Call.Calls[r.CallID].WhoHungUp = ((IpPacket)udpPacket.ParentPacket).SourceAddress == Call.Calls[r.CallID].CallerIP ?
                                        Call.CallDirection.Caller : Call.CallDirection.Callee;
                                }
                                else
                                {
                                    Console.WriteLine("Unknown CallID: " + r.CallID);
                                }
                            }
                        }
                        else if (msg is SIP_Response && msg.CallID != null)
                        {
                            SIP_Response r = (SIP_Response)msg;

                            if (sdp != null)
                            {
                                foreach (var a in sdp.MediaDescriptions)
                                {
                                    Console.Out.WriteLine(r.CallID + " - Got RTP Media Port: " + ((IpPacket)udpPacket.ParentPacket).SourceAddress + ":" + a.Port.ToString());
                                    if (Call.Calls[r.CallID].CallerIP.ToString() == ((IpPacket)udpPacket.ParentPacket).SourceAddress.ToString())
                                        Call.Calls[r.CallID].CallerRTPPort = a.Port;
                                    else
                                        Call.Calls[r.CallID].CalleeRTPPort = a.Port;
                                }
                            }

                            if(Call.Calls.ContainsKey(r.CallID))
                                if (r.StatusCodeType == SIP_StatusCodeType.Success && Call.Calls[r.CallID].SeenBYE)
                                {
                                    Call.Calls[r.CallID].Confirmed = true;
                                }
                        }

                        // Add packet to history
                        if (Call.Calls.ContainsKey(msg.CallID))
                        {
                            Call.Calls[msg.CallID].WritePacket(e.Packet, Call.PacketType.SIPDialog);
                            // Check to see is this call has been terminated
                            if (Call.Calls[msg.CallID].Confirmed)
                            {
                                // Close off the call now last data has been written
                                Console.WriteLine("Call Ended: " + msg.CallID);
                                // Close off the call
                                Call.Calls[msg.CallID].CloseCall();
                            }
                        }
                    }
                    else
                    {
                        Call c = Call.GetCallByRTPPort(udpPacket.SourcePort);
                        if (c != null)
                            c.WritePacket(e.Packet, Call.PacketType.RTP);
                    }
                }
                catch(Exception ex){
                    Console.WriteLine(ex.ToString());
                }
            }
            
        }
    }
}
