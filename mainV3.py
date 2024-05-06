import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from scapy.all import *
import matplotlib.pyplot as plt
import dpkt
import socket

#global variables
selectedFilename = None

#function which analyzes packets and displays the amount of protocols
def amountOfProtocols():
    global selectedFilename
    if selectedFilename:
        try:
            #prompt the user for the starting and ending points for packet analysis
            start_end_points = simpledialog.askstring("Packet Analysis", "Enter the starting and ending packet numbers for analysis (e.g., start-end):")
            start_point, end_point = map(int, start_end_points.split('-'))

            #read the pcap file
            packets = rdpcap(selectedFilename)

            #extract the specified range of packets
            packets = packets[start_point - 1:end_point]

            #initialize counters for different types of packets
            tcp_count = 0
            udp_count = 0
            icmp_count = 0

            #analyze each packet
            for packet in packets:
                if TCP in packet:
                    tcp_count += 1
                elif UDP in packet:
                    udp_count += 1
                elif ICMP in packet:
                    icmp_count += 1

            #update the text in the resultsText widget
            resultsText.config(state=tk.NORMAL)
            #resultsText.delete("1.0", tk.END) #deletes all previous text
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
            address = simpledialog.askstring("Packet Analysis", "Enter the source IP address:")
            sequenceList, dportList = getPorts(selectedFilename, address)
            graphType = simpledialog.askstring("Generate Graph", "Enter the type of graph (plot, bar, stackplot, step):")
            plotGraph(sequenceList, dportList, graphType)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        messagebox.showerror("Error", "No file selected. Please select a file first.")

#function to extract ports from packets
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

#function to plot graph
def plotGraph(sequenceList, dportList, graphType):
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

#function to exit the application
def exitApplication():
    if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
        root.destroy()

#create the main application window
root = tk.Tk()
root.title("Sakibs Network Analysis Tool")
#set the window size
root.geometry("1024x600")  #width x height

#load the background image
image_path = "background.png"  #specify the path to your background image
background_image = Image.open(image_path)
background_image = ImageTk.PhotoImage(background_image)

#create a canvas to display the background image
canvas = tk.Canvas(root, width=1024, height=600)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=background_image)

#create buttons for file opening, packet analysis, and generate graph
openButton = tk.Button(root, text="Open PCAP File", command=fileOpener)
analyzeButton = tk.Button(root, text="Analyze Packets", command=amountOfProtocols)
graphButton = tk.Button(root, text="Generate Graph", command=generateGraph)
exitButton = tk.Button(root, text="Exit Application", command=exitApplication)

#add buttons to the canvas
canvas.create_window(200, 100, anchor="nw", window=openButton)
canvas.create_window(300, 100, anchor="nw", window=analyzeButton)
canvas.create_window(400, 100, anchor="nw", window=graphButton)
canvas.create_window(500, 100, anchor="nw", window=exitButton)

#create a text box to display analysis results
resultsText = tk.Text(root, height=20, width=80)
resultsText.pack()
resultsText.place(x=200, y=140)
resultsText.insert(tk.END, "Welcome to the Network Analysis Tool!\n")
resultsText.insert(tk.END, "Start by opening a PCAP file and then choosing one of the options above\n\n")
resultsText.config(state=tk.DISABLED)  #makes the text box read-only

#run the program
root.mainloop()
