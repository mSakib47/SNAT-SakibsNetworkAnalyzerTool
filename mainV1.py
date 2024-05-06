import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from scapy.all import *

#global variables
selectedFilename = None

#function which analyzes packets and displays amount of protocols
def amountOfProtocols():
    global selectedFilename
    if selectedFilename:
        try:
            #prompt the user for the starting and ending points for packet analysis
            start_point = simpledialog.askinteger("Packet Analysis", "Enter the starting point for packet analysis:")
            end_point = simpledialog.askinteger("Packet Analysis", "Enter the ending point for packet analysis:")

            #read the pcap file
            packets = rdpcap(selectedFilename)

            #extract the specified range of packets
            packets = packets[start_point - 1:end_point]

            #initialize counters for different types of packets
            tcp_count = 0
            udp_count = 0
            icmp_count = 0

            # Analyze each packet
            for packet in packets:
                if TCP in packet:
                    tcp_count += 1
                elif UDP in packet:
                    udp_count += 1
                elif ICMP in packet:
                    icmp_count += 1

            # Update the text in the resultsText widget
            resultsText.config(state=tk.NORMAL)
            resultsText.delete("1.0", tk.END)
            resultsText.insert(tk.END, f"Showing protocols from range {start_point} to {end_point}:\n")
            resultsText.insert(tk.END, f"TCP packets: {tcp_count}\n")
            resultsText.insert(tk.END, f"UDP packets: {udp_count}\n")
            resultsText.insert(tk.END, f"ICMP packets: {icmp_count}\n\n")
            resultsText.insert(tk.END, "Packet Analysis Results:\n")
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

#create the main application window
root = tk.Tk()
root.title("Sakibs Network Analysis Tool")
#set the window size
root.geometry("1024x600")  #width x height

#load the background image
image_path = "background.png"  # Specify the path to your background image
background_image = Image.open(image_path)
background_image = ImageTk.PhotoImage(background_image)

#create a canvas to display the background image
canvas = tk.Canvas(root, width=1024, height=600)
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=background_image)

#create buttons for file opening and packet analysis
openButton = tk.Button(root, text="Open PCAP File", command=fileOpener)
analyzeButton = tk.Button(root, text="Analyze Packets", command=amountOfProtocols)

#add buttons to the canvas
canvas.create_window(200, 100, anchor="nw", window=openButton)
canvas.create_window(300, 100, anchor="nw", window=analyzeButton)

#create a text box to display analysis results
resultsText = tk.Text(root, height=20, width=80)
resultsText.pack()
resultsText.place(x=200, y=140)
resultsText.insert(tk.END, "Packet Analysis Results:\n\n")
resultsText.config(state=tk.DISABLED)  # Make the text box read-only

#run the program
root.mainloop()