import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from scapy.all import *
import matplotlib.pyplot as plt
import dpkt
import socket
import threading

# global variables
selectedFilename = None

# function which analyzes packets and displays the amount of protocols
def amountOfProtocols():
    global selectedFilename
    if selectedFilename:
        try:
            # prompt the user for the starting and ending points for packet analysis
            start_end_points = simpledialog.askstring("Packet Analysis", "Enter the starting and ending packet numbers\nfor analysis starting from 1 (e.g., start-end):")
            start_point, end_point = map(int, start_end_points.split('-'))

            # read the pcap file
            packets = rdpcap(selectedFilename)

            # extract the specified range of packets
            packets = packets[start_point - 1:end_point]

            # initialize counters for different types of packets
            tcp_count = 0
            udp_count = 0
            icmp_count = 0

            # analyze each packet
            for packet in packets:
                if TCP in packet:
                    tcp_count += 1
                elif UDP in packet:
                    udp_count += 1
                elif ICMP in packet:
                    icmp_count += 1

            # update the text in the resultsText widget
            resultsText.config(state=tk.NORMAL)
            resultsText.insert(tk.END, f"Packet Analysis Results for {selectedFilename}:\n\n")
            resultsText.insert(tk.END, f"Showing protocols from range {start_point} to {end_point}:\n")
            resultsText.insert(tk.END, f"TCP packets: {tcp_count}\n")
            resultsText.insert(tk.END, f"UDP packets: {udp_count}\n")
            resultsText.insert(tk.END, f"ICMP packets: {icmp_count}\n\n")
            resultsText.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        messagebox.showerror("Error", "No file selected. Please select a file first.")

# function handles all the file opening
def fileOpener():
    global selectedFilename
    # open a dialog window to select a file with a .pcap extension
    filename = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    # if the file name is selected, return the message
    if filename:
        selectedFilename = filename
        messagebox.showinfo("File Selected", f"You selected: {filename}")
        resultsText.config(state=tk.NORMAL)
        resultsText.insert(tk.END, f"{filename} has been selected\n\n")
        resultsText.config(state=tk.DISABLED)

# function to generate graph of ports vs sequence numbers
def generateGraph():
    global selectedFilename
    if selectedFilename:
        try:
            address = simpledialog.askstring("Packet Analysis", "Enter the source IP Address:\n\n"
                                                                "Example IP Addresses:\n"
                                                                "(192.168.56.101, 192.168.56.104, 192.168.56.1)\n")

            if address is None:  # check if the user canceled the dialog
                return

            # create a new window for graph type selection
            graphTypeWindow = tk.Toplevel(root)
            graphTypeWindow.title("Graph Type")
            graphTypeWindow.geometry("315x150")

            # calculate the position to center the window on the screen
            window_width = graphTypeWindow.winfo_reqwidth()
            window_height = graphTypeWindow.winfo_reqheight()
            position_right = int(graphTypeWindow.winfo_screenwidth() / 2 - window_width / 2)
            position_down = int(graphTypeWindow.winfo_screenheight() / 2 - window_height / 2)

            # set the window position
            graphTypeWindow.geometry(f"+{position_right}+{position_down}")

            # create widgets for graph type selection
            graphTypeLabel = tk.Label(graphTypeWindow, text="Select the type of graph:\n"
                                                            "Press button again to change colour of graph\n"
                                                            "(Please be patient whilst selecting multiple graphs at once)")
            graphTypeLabel.grid(row=0, column=0, columnspan=2, pady=10)

            # create buttons for each graph type
            plotButton = tk.Button(graphTypeWindow, text="Plot", command=lambda: plotGraph(address, "plot", graphTypeWindow))
            plotButton.grid(row=2, column=0, padx=10, pady=5)
            barButton = tk.Button(graphTypeWindow, text="Bar", command=lambda: plotGraph(address, "bar", graphTypeWindow))
            barButton.grid(row=2, column=1, padx=10, pady=5)
            stackButton = tk.Button(graphTypeWindow, text="Stack", command=lambda: plotGraph(address, "stack", graphTypeWindow))
            stackButton.grid(row=3, column=0, padx=10, pady=5)
            stepButton = tk.Button(graphTypeWindow, text="Step", command=lambda: plotGraph(address, "step", graphTypeWindow))
            stepButton.grid(row=3, column=1, padx=10, pady=5)

            # set the main window as the parent and make it inactive while the popup is open
            graphTypeWindow.transient(root)
            graphTypeWindow.grab_set()

            # wait until the popup window is closed
            root.wait_window(graphTypeWindow)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        messagebox.showerror("Error", "No file selected. Please select a file first.")

# function to extract ports from packets
def getPorts(filename, address):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    sequenceList = []
    dportList = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if type(ip.data) == dpkt.tcp.TCP:
            tcp = ip.data
            sourceIP = socket.inet_ntoa(ip.src)
            if sourceIP == address:
                sequenceList.append(ts)
                dportList.append(tcp.dport)
    f.close()
    return sequenceList, dportList

# function to plot graph
def plotGraph(address, graphType, graphTypeWindow):
    sequenceList, dportList = getPorts(selectedFilename, address)
    if graphType in ["bar", "bar chart"]:
        plt.bar(sequenceList, dportList)
    elif graphType in ["stack", "stack plot"]:
        plt.stackplot(sequenceList, dportList)
    elif graphType == "step":
        plt.step(sequenceList, dportList)
    else:
        plt.plot(sequenceList, dportList)
    plt.title("Ports vs Sequence Numbers")
    plt.xlabel('Time Stamp')
    plt.ylabel('Port Number')
    plt.show()

# function to initiate packet sniffing
def startPacketSniffing():
    iface = get_interface()
    threading.Thread(target=sniff_traffic, args=(iface,)).start()

def sniff_traffic(iface):
    try:
        sniff(iface=iface, store=False, prn=process_packet)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during packet sniffing: {str(e)}")

def process_packet(packet):
    # Process each packet here
    # You can customize this function to analyze and display packet information
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        keys = ["username".encode('utf-8'), "password".encode('utf-8'), "pass".encode('utf-8'), "email".encode('utf-8')]
        for key in keys:
            if key in load:
                info = f"\n\n\n[+] Possible username/password >> {load.decode('utf-8')}\n\n\n"
                resultsText.config(state=tk.NORMAL)
                resultsText.insert(tk.END, info)
                resultsText.config(state=tk.DISABLED)
                break


def get_interface():
    interface = simpledialog.askstring("Interface Selection", "Select network interface:\n"
                                                              "(Refer to manual)\n"
                                       "Example: Ethernet, WiFi", parent=root)
    print("Using interface:", interface)
    resultsText.config(state=tk.NORMAL)
    resultsText.insert(tk.END, f"Starting Packet Sniffer using interface: {interface}\n"
                       "Example HTTP Website to visit: http://testphp.vulnweb.com/login.php \n")
    resultsText.config(state=tk.DISABLED)
    return interface

# function to exit the application
def exitApplication():
    if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
        root.destroy()

# create the main application window
root = tk.Tk()
root.title("Sakibs Network Analysis Tool")
# set the window size
root.geometry("1024x600")  # width x height

# load the background image
image_path = "background.png"  # specify the path to your background image
background_image = Image.open(image_path)
background_image = ImageTk.PhotoImage(background_image)

# create a canvas to display the background image
canvas = tk.Canvas(root, width=1024, height=600)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=background_image)

# create buttons for file opening, packet analysis, and generate graph
openButton = tk.Button(root, text="Open PCAP File", command=fileOpener)
analyzeButton = tk.Button(root, text="Analyze Packets", command=amountOfProtocols)
graphButton = tk.Button(root, text="Generate Graph", command=generateGraph)
exitButton = tk.Button(root, text="Exit Application", command=exitApplication)
sniffButton = tk.Button(root, text="Start Packet Sniffing", command=startPacketSniffing)

# add buttons to the canvas
canvas.create_window(200, 100, anchor="nw", window=openButton)
canvas.create_window(300, 100, anchor="nw", window=analyzeButton)
canvas.create_window(400, 100, anchor="nw", window=graphButton)
canvas.create_window(500, 100, anchor="nw", window=exitButton)
canvas.create_window(600, 100, anchor="nw", window=sniffButton)

# create a text box to display analysis results
resultsText = tk.Text(root, height=20, width=80)
resultsText.pack()
resultsText.place(x=200, y=140)
resultsText.insert(tk.END, "Welcome to the Network Analysis Tool!\n")
resultsText.insert(tk.END, "Start by opening a PCAP file and then choosing one of the options above\n\n")
resultsText.config(state=tk.DISABLED)  # makes the text box read-only

# run the program
root.mainloop()
