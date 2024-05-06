import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from scapy.all import *
from scapy.layers.inet import TCP, UDP
import matplotlib.pyplot as plt
import dpkt
import socket
import threading
from threading import Thread
import sys
import time
import nmap

#global variables
selectedFilename = None #selected file at start is nothing
sniffingThread = None  #to keep track of the sniffing thread
livegraphPacketCount = 0 #sets initial packetCount for live graph to 0
stopSniffing = False #sets stopSniffing to false originally
ipAddress = 0 #sets initial ip address value to 0
nmapScanComplete = False #creates a boolean variable for when the nmap scan is complete

#function which analyzes packets and displays the amount of protocols
def amountOfProtocols():
    global selectedFilename
    if selectedFilename:
        try:
            #prompt the user for the starting and ending points for packet analysis
            startEndPoints = simpledialog.askstring("Packet Analysis", "Enter the starting and ending packet numbers\nfor analysis starting from 1 (e.g., start-end):")
            startPoint, endPoint = map(int, startEndPoints.split('-'))

            #read the pcap file
            packets = rdpcap(selectedFilename)

            #extract the specified range of packets
            packets = packets[startPoint - 1:endPoint]

            #initialize counters for different types of packets
            tcpCount = 0
            udpCount = 0
            otherCount = 0

            #analyze each packet
            for packet in packets:
                if TCP in packet:
                    tcpCount += 1
                elif UDP in packet:
                    udpCount += 1
                else:
                    otherCount += 1

            #update the text in the resultsText widget
            resultsText.config(state=tk.NORMAL)
            resultsText.insert(tk.END, f"Packet Analysis Results for {selectedFilename}:\n\n")
            resultsText.insert(tk.END, f"Showing protocols from range {startPoint} to {endPoint}:\n")
            resultsText.insert(tk.END, f"TCP packets: {tcpCount}\n")
            resultsText.insert(tk.END, f"UDP packets: {udpCount}\n")
            resultsText.insert(tk.END, f"Other packets: {otherCount}\n\n")
            resultsText.config(state=tk.DISABLED)

        #catches any errors that may occur in the code above and alerts user rather then crashing application
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        messagebox.showerror("Error", "No file selected. Please select a file first.")

#function handles all the file opening
def fileOpener():
    global selectedFilename
    #open a dialog window to select a file with a .pcap extension
    filename = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    #if the file name is selected, return the message
    if filename:
        selectedFilename = filename
        messagebox.showinfo("File Selected", f"You selected: {filename}")
        resultsText.config(state=tk.NORMAL)
        resultsText.insert(tk.END, f"{filename} has been selected\n\n")
        resultsText.config(state=tk.DISABLED)

#function to generate graph of ports vs sequence numbers
def generateGraph():
    global selectedFilename
    if selectedFilename:
        try:
            address = simpledialog.askstring("Packet Analysis", "Enter the source IP Address:\n\n"
                                                                "Example IP Addresses:\n"
                                                                "(192.168.56.101, 192.168.56.104, 192.168.56.1)\n")

            if address is None:  #check if the user canceled the dialog
                return

            #create a new window for graph type selection
            graphTypeWindow = tk.Toplevel(root)
            graphTypeWindow.title("Graph Type")
            graphTypeWindow.geometry("315x150")

            #calculate the position to center the window on the screen
            windowWidth = graphTypeWindow.winfo_reqwidth()
            windowHeight = graphTypeWindow.winfo_reqheight()
            positionRight = int(graphTypeWindow.winfo_screenwidth() / 2 - windowWidth / 2)
            positionDown = int(graphTypeWindow.winfo_screenheight() / 2 - windowHeight / 2)

            #set the window position
            graphTypeWindow.geometry(f"+{positionRight}+{positionDown}")

            #create widgets for graph type selection
            graphTypeLabel = tk.Label(graphTypeWindow, text="Select the type of graph:\n"
                                                            "Press button again to change colour of graph\n"
                                                            "(Please be patient whilst selecting multiple graphs at once)")
            graphTypeLabel.grid(row=0, column=0, columnspan=2, pady=10)

            #create buttons for each graph type
            plotButton = tk.Button(graphTypeWindow, text="Plot", command=lambda: plotGraph(address, "plot", graphTypeWindow))
            plotButton.grid(row=2, column=0, padx=10, pady=5)
            barButton = tk.Button(graphTypeWindow, text="Bar", command=lambda: plotGraph(address, "bar", graphTypeWindow))
            barButton.grid(row=2, column=1, padx=10, pady=5)
            stackButton = tk.Button(graphTypeWindow, text="Stack", command=lambda: plotGraph(address, "stack", graphTypeWindow))
            stackButton.grid(row=3, column=0, padx=10, pady=5)
            stepButton = tk.Button(graphTypeWindow, text="Step", command=lambda: plotGraph(address, "step", graphTypeWindow))
            stepButton.grid(row=3, column=1, padx=10, pady=5)

            #set the main window as the parent and make it inactive while the popup is open
            graphTypeWindow.transient(root)
            graphTypeWindow.grab_set()

            #wait until the popup window is closed
            root.wait_window(graphTypeWindow)

        # catches any errors that may occur in the code above and alerts user rather then crashing application
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        messagebox.showerror("Error", "No file selected. Please select a file first.")

#function to extract ports from packets
def getPorts(filename, address):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    #create empty lists to store timestamps and destination ports
    sequenceList = []
    dportList = []
    #loop through the packets in the pcap file
    for ts, buf in pcap:
        #gather the ethernet and ip layers of the packet
        ethernetLayer = dpkt.ethernet.Ethernet(buf)
        ipLayer = ethernetLayer.data
        #if its a tcp packet get the source IP
        if type(ipLayer.data) == dpkt.tcp.TCP:
            tcp = ipLayer.data
            sourceIP = socket.inet_ntoa(ipLayer.src)
            #if the sourceIP matches the provided address add it to the graph
            if sourceIP == address:
                sequenceList.append(ts)
                dportList.append(tcp.dport)
    f.close()
    return sequenceList, dportList

#function to plot graph for pcap files
def plotGraph(address, graphType, graphTypeWindow):
    sequenceList, dportList = getPorts(selectedFilename, address)
    #plot graph depending on type of graph selected
    if graphType in ["bar", "bar chart"]:
        plt.bar(sequenceList, dportList)
    elif graphType in ["stack", "stack plot"]:
        plt.stackplot(sequenceList, dportList)
    elif graphType == "step":
        plt.step(sequenceList, dportList)
    else:
        plt.plot(sequenceList, dportList)
    #label axis and display the graph
    plt.title("Ports vs Sequence Numbers")
    plt.xlabel('Time Stamp')
    plt.ylabel('Port Number')
    plt.show()

#function which increases the packet count of live graph for each packet
def livegraphPacketHandler(packet):
    global livegraphPacketCount
    livegraphPacketCount += 1

#function that plots the livegraph
def plotLivegraph():
    global livegraphPacketCount
    plt.ion()  #turn on interactive mode for matplotlib
    y = [] #empty list to store packet count

    while True:
        y.append(livegraphPacketCount) #add the current packet to the list
        plt.clf() #clear the graph
        plt.plot(y) #plot the new updated graph
        plt.xlabel('Time in seconds')  #label for x-axis
        plt.ylabel('Number of Packets')  #label for y-axis
        plt.pause(0.1) #pause for a short period to allow the graph to update

        #reset packet count
        livegraphPacketCount = 0
        #check if the figure is closed
        if not plt.get_fignums():
            break
        #pause for a second so graph is scanned every second
        time.sleep(1)

#function which generates the livegraph
def generateLiveGraph():
    #start the packet sniffing in a separate thread
    snifferThread = Thread(target=sniff, kwargs={'prn': livegraphPacketHandler})
    snifferThread.start()

    #update text box
    resultsText.config(state=tk.NORMAL)
    resultsText.insert(tk.END, f"Generating a live graph of your current network:\n"
                               f"X-Axis represents the time in seconds\n"
                               f"Y-Axis represents the amount of packets being transmitted over current network\n\n")
    resultsText.config(state=tk.DISABLED)

    #start the live plotting in the main thread
    plotLivegraph()

#function to start packet sniffing
def startPacketSniffing():
    global sniffingThread, stopSniffing
    stopSniffing = False #set to false to allow it packet sniffing to start
    #make sure no current thread of packet sniffing is running
    if sniffingThread is None or not sniffingThread.is_alive():
        iface = getInterface() #get the network interface from user
        #start a new thread for the packet sniffing
        sniffingThread = threading.Thread(target=sniffTraffic, args=(iface,))
        sniffingThread.start()
    #if packet sniffing is already running warn user
    else:
        messagebox.showwarning("Warning", "Packet sniffing is already running.")

#function that stops packet sniffing
def stopPacketSniffing():
    global sniffingThread, stopSniffing
    #checks if there is a current thread of sniffing running
    if sniffingThread is not None and sniffingThread.is_alive():
        stopSniffing = True #stop the packet sniffer
        sniffingThread.join() #wait for the sniffer to stop and then alert the user
        messagebox.showinfo("Info", "Packet sniffing stopped successfully.")
    #if not packet sniffer is running alert user
    else:
        messagebox.showwarning("Warning", "Packet sniffing is currently not running.")

#function which sniffs through packets
def sniffTraffic(iface):
    global stopSniffing
    try:
        while not stopSniffing: #only run when sniffer is not stopped
            sniff(iface=iface, store=False, prn=processPacket, count = 10) #sniff in small batches
    #catch any errors and exceptions and alert user
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during packet sniffing: {str(e)}")

def processPacket(packet):
    #process each packet here
    #if the packet has a raw layer which can contain a possible password
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load #load the data
        #create the keys which could contain sensitive data
        keys = ["username".encode('utf-8'), "password".encode('utf-8'), "pass".encode('utf-8'), "email".encode('utf-8')]
        #loop through the keys and print info into text box
        for key in keys:
            if key in load:
                info = f"\n\n\n[+] Possible username/password >> {load.decode('utf-8')}\n\n\n"
                resultsText.config(state=tk.NORMAL)
                resultsText.insert(tk.END, info)
                resultsText.config(state=tk.DISABLED)
                break

#function which asks user for what interface they want to scan
def getInterface():
    interface = simpledialog.askstring("Interface Selection", "Select network interface:\n"
                                                              "(Refer to manual)\n"
                                       "Example: Ethernet, WiFi", parent=root)
    print("Using interface:", interface)
    resultsText.config(state=tk.NORMAL)
    resultsText.insert(tk.END, f"Starting Packet Sniffer using interface: {interface}\n"
                       "Example HTTP Website to visit: http://testphp.vulnweb.com/login.php \n")
    resultsText.config(state=tk.DISABLED)
    return interface

#function which takes inputs ready for an nmap scan
def nmapScan():
    global ipAddress, Nmap
    nmapScanComplete = False #set the current completion state as false
    #set Nmap variable as the portscanner for easy access
    Nmap = nmap.PortScanner()
    ipAddress = simpledialog.askstring("Nmap Scan", "Enter the IP address you want to scan on your network:\n"
                                                    "Usually 192.168.1.X <-- replace X\n")
    #checks if the IP address is valid using the ipAddressChecker function below
    if not ipAddressChecker(ipAddress):
        resultsText.config(state=tk.NORMAL)
        resultsText.insert(tk.END, f"Invalid IP address: {ipAddress}\n\n")
        resultsText.config(state=tk.DISABLED)
        return
    resultsText.config(state=tk.NORMAL)
    resultsText.insert(tk.END, f"Performing an Nmap Scan on: {ipAddress}\n"
                               f"Please wait..\n\n")
    resultsText.config(state=tk.DISABLED)
    #delay the nmap scan so user can be notified its in progress
    resultsText.after(1000, nmapScanCheck)  #schedule the scan to start after 1 second

#function which checks if an IP address is valid
def ipAddressChecker(ip):
    #split the ip address into segments
    segments = ip.split(".")
    if len(segments) != 4: #if the ip address doesnt have 4 segments return false
        return False
    for segment in segments:
        #if the segments arent integers or in between the range 0-255 return false
        if not segment.isdigit() or not 0 <= int(segment) <= 255:
            return False
        return True #return true if it passes the checks

#function which runs the nmap scan
def runNmapScan():
    global Nmap, nmapScanComplete
    nmapResult = Nmap.scan(ipAddress, "22-443") #range of protocols to be scanned
    #display the results of the nmap scan into the text box
    resultsText.config(state=tk.NORMAL)
    #resultsText.insert(tk.END, nmapResult)
    #loops over all the IP addresses that were scanned and displays them into the text box
    for host in Nmap.all_hosts():
        resultsText.insert(tk.END, f'Showing Nmap Scan for IP address: {host} {Nmap[host].hostname()}\n')
        resultsText.insert(tk.END, f'State: {Nmap[host].state()}\n')
        #loops over all the protocols of the current host and displays them in text box
        for protocol in Nmap[host].all_protocols():
            resultsText.insert(tk.END, f'Protocol: {protocol}\n')
            localport = Nmap[host][protocol].keys() #get all the ports of the current protocol
            #loops over all the ports and display them into the text box
            for port in localport:
                resultsText.insert(tk.END, f'port: {port}\tstate: {Nmap[host][protocol][port]["state"]}\n\n')
    resultsText.config(state=tk.DISABLED)
    nmapScanComplete = True #set the completion state to true

def nmapScanCheck():
    #start the timer and the nmap scan
    startTime = time.time()
    runNmapScan()
    #check every second if the scan has been running for more than 20 seconds
    while True:
        time.sleep(1)  #wait for 1 second
        #break the loop if the nmap scan is completed
        if nmapScanComplete:
            break
        if time.time() - startTime > 20:
            resultsText.config(state=tk.NORMAL)
            resultsText.insert(tk.END, "Nmap Scan timed out after 20 seconds\n"
                                       "Most likely an incorrect IP address was used\n\n")
            resultsText.config(state=tk.DISABLED)
            break  #exit the loop


#function to display help information
def displayHelp():
    helpText = """
MANUAL FOR SAKIBS NETWORK ANALYZER TOOL:

Opening PCAP files:
In the zip file there are three example PCAP files you can use to test the software.
These PCAP files can be used with the packet analyzer button and graph generation.

PCAP Protocol Counter:
This button will count the amount of TCP and UDP packets in the PCAP file selected by user
It will ask the user to input the range they want to check.

Example PCAP files graph visualization:
For the first pcap file it is recommended to use the following IP addresses:
192.168.56.101
192.168.56.104

At the timestamp of 450, the amount of ports being accessed is very high suggesting that the user
is scanning everysingle port on the network using an nmap scan.

For the second pcap file it is recommended to use the following IP addresses:
192.158.56.1
192.168.56.101

Normal user access and then a brute force attack occurs out of nowhere.

For the third pcap file it is recommended to use the following IP addresses:
192.168.56.1
182.168.56.102

Brute force attack using a specfic pattern of passwords occurs.

Packet Sniffer:
PLEASE DO NOT USE PACKET SNIFFER ON UNAUTHROISED NETWORKS.
The software is intended for demonstration purposes and hence only works on test HTTP websites
which are intentionally vulnerable and dont use HTTPS.

Below are a couple intentionally vulnerable websites you can use:
http://testphp.vulnweb.com/login.php
http://vbsca.ca/login/login.asp

For the packet sniffer it is required that you figure out the name of your network interface so
the packet sniffer can understand which network interface it is meant to scan.
The first method is to just use the default simple names of Ethernet or WiFi,
however if this doesnt work it is required to find the exact name of the interface card using the steps below:

To do this it is very simple, all you have to do is go to:
Control panel, select Network and Sharing Center.
Click change adapter settings.
Select your network type e.g Ethernet/WiFi
Click details button and it should say it in the description.
Usually looks like:
Realtek PCIe GbE Family Controller,
Intel(R) Dual Band Wireless-AC 7260
More information on https://support.lenovo.com/gt/en/solutions/ht078107-how-to-find-and-download-network-driver-windows

Live graph visualization:
This button will generate a live plot graph of the network you are connected to using matplotlib,
The X-Axis represents the time in seconds and the
Y-Axis represents the amount of packets being transmitted over the current network.

Nmap Scan:
It is required to have the actual Nmap installed on your computer aswell as the library. 
Its a simple download on Windows from: https://nmap.org/download

It will ask the user to input a valid IP address on their network that they want to scan
Then it will scan the IP address from the protocol range 22-443
and provide a list of open ports and the status of the IP address.

It has a validation function which will test that a correct IP address is inputed
It will also time out after 20 seconds if the port scan is taking too long.
    """
    messagebox.showinfo("Help", helpText)

#function to exit the application
def exitApplication():
    if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
        root.destroy() #closes the gui
        sys.exit() #completely stops the python application

#create the main application window
root = tk.Tk()
root.title("Sakibs Network Analysis Tool")
#set the window size
root.geometry("1024x600")  #width x height

#load the background image
imagePath = "background.png"  #specify the path to your background image
backgroundImage = Image.open(imagePath)
backgroundImage = ImageTk.PhotoImage(backgroundImage)

#create a canvas to display the background image
canvas = tk.Canvas(root, width=1024, height=600)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=backgroundImage)

#create buttons for file opening, packet analysis, and generate graph
openButton = tk.Button(root, text="Open PCAP File", command=fileOpener)
protocolButton = tk.Button(root, text="Protocol Counter", command=amountOfProtocols)
graphButton = tk.Button(root, text="Generate Graph", command=generateGraph)
liveGraphButton = tk.Button(root, text="Generate Live Graph", command=generateLiveGraph)
sniffButton = tk.Button(root, text="Start Packet Sniffing", command=startPacketSniffing)
stopSniffButton = tk.Button(root, text="Stop Packet Sniffing", command=stopPacketSniffing)
nmapButton = tk.Button(root, text="Nmap Scan", command=nmapScan)
helpButton = tk.Button(root, text="Click this button for Help on how to use the Application", command=displayHelp)
exitButton = tk.Button(root, text="Exit Application", command=exitApplication)

#add buttons to the canvas
canvas.create_window(200, 65, anchor="nw", window=openButton)
canvas.create_window(300, 65, anchor="nw", window=protocolButton)
canvas.create_window(408, 65, anchor="nw", window=graphButton)
canvas.create_window(200, 100, anchor="nw", window=liveGraphButton)
canvas.create_window(323, 100, anchor="nw", window=sniffButton)
canvas.create_window(446, 100, anchor="nw", window=stopSniffButton)
canvas.create_window(569, 100, anchor="nw", window=nmapButton)
canvas.create_window(200, 480, anchor="nw", window=helpButton)
canvas.create_window(750, 100, anchor="nw", window=exitButton)

#create a text box to display analysis results
resultsText = tk.Text(root, height=20, width=80)
resultsText.pack()
resultsText.place(x=200, y=140)
resultsText.insert(tk.END, "Welcome to the Network Analysis Tool!\n")
resultsText.insert(tk.END, "Start by choosing one of the options above\n")
resultsText.insert(tk.END, "Press the help button below for more information\n")
resultsText.insert(tk.END, '--------------------------------------------------------------------------------\n\n')
resultsText.config(state=tk.DISABLED)  #makes the text box read-only

#run the program
root.mainloop()
