#  Christopher Grimsley
#  CSS212
#  NET2 Network tool

import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import psutil
import nmap
import subprocess
import platform
import time

MAX_SPEED = 10 ** 7  # Max speed used in the progress bar, value = kbps.

"""This function uses psutil to pull network usage data to show to the user in the GUI. A progress bar is rendered using
MAX_SPEED to visualize how much data is being used by the system. We use a sleep to ensure the program has data to
display before it displays the data usage. All usage is shown as KB/s. Finally we continually update the data so the
program can give near-realtime info to the user."""


def fetch_network_usage(dow):
    def update_usage():
        old_stats = psutil.net_io_counters()
        time.sleep(1)
        new_stats = psutil.net_io_counters()

        bytes_sent = new_stats.bytes_sent - old_stats.bytes_sent
        bytes_recv = new_stats.bytes_recv - old_stats.bytes_recv

        # Calculate upload and download rates
        upload_rate = bytes_sent  # Assuming 1 second elapsed
        download_rate = bytes_recv  # Assuming 1 second elapsed

        # Update the GUI components with the calculated rates
        tab4.after(0, lambda: upload_progress.configure(value=min(upload_rate, MAX_SPEED)))
        tab4.after(0, lambda: download_progress.configure(value=min(download_rate, MAX_SPEED)))
        tab4.after(0, lambda: upload_label.configure(text=f"Upload Speed: {upload_rate / 1024:.2f} KB/s"))
        tab4.after(0, lambda: download_label.configure(text=f"Download Speed: {download_rate / 1024:.2f} KB/s"))

        # Reschedule the update
        tab4.after(1000, update_usage)

    # Start background thread
    threading.Thread(target=update_usage, daemon=True).start()


"""This function constantly pings google when active to give the user latency and packet loss analytics. This is done
by using platform.system() to determine the OS of the system so we can issue a ping command to get the data. If the OS
is not Windows the program will not be able to display latency data correctly."""


def ping_target(target='8.8.8.8', count=4):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), target]
        ping_output = subprocess.run(command, stdout=subprocess.PIPE, text=True)
        output_lines = ping_output.stdout.splitlines()

        #  output for packet loss and latency
        packet_loss = [line for line in output_lines if "loss" in line.lower()]
        latency_line = [line for line in output_lines if "average" in line.lower() or "min/avg/max" in line.lower()]

        packet_loss_info = packet_loss[0].split(",")[-2] if packet_loss else "Packet loss info not available"
        latency_info = latency_line[0].split("=")[-1].strip() if latency_line else "Latency info not available"
        return packet_loss_info, latency_info
    except Exception as e:
        return f"Error: {str(e)}", "Latency info not available"


"""This function is used to routinely update the info from the ping_target function. This function also gives us a
proper place and way to optimize the function so it does not lag or crash on the user (or at least it shouldn't)."""


def update_network_health():
    def thread_ping():
        packet_loss_info, latency_info = ping_target()
        # Schedule the GUI update
        tab3.after(0, lambda: network_health_label.config(
            text=f"Packet Loss: {packet_loss_info}\nLatency: {latency_info}"))
        tab3.after(10000, update_network_health)  # Schedule the next update

    # Run the ping in a separate thread
    threading.Thread(target=thread_ping, daemon=True).start()


"""This function uses psutil to pull the network connections currently being made by the system. It also facilitates
our query ability."""


def get_active_connections(filter_ip=None, filter_port=None):
    connections = psutil.net_connections(kind='inet')
    if filter_ip or filter_port:
        filtered_connections = []
        for conn in connections:
            if filter_ip and filter_ip != conn.laddr.ip:
                continue
            if filter_port and filter_port != str(conn.laddr.port):
                continue
            filtered_connections.append(conn)
        return filtered_connections
    return connections


"""This function continuously pulls the network connections currently being made by the system and updates the GUI. """


def update_connections(filter_ip=None, filter_port=None, auto_refresh_rate=10000):
    for i in tree.get_children():
        tree.delete(i)  # Clear the treeview
    connections = get_active_connections(filter_ip, filter_port)
    for conn in connections:
        tree.insert("", "end",
                    values=(conn.laddr.ip, conn.laddr.port, conn.raddr.ip if conn.raddr else 'N/A', conn.status))

    # Schedule the next update
    if auto_refresh_rate:
        tree.after(auto_refresh_rate, lambda: update_connections(filter_ip, filter_port, auto_refresh_rate))


"""This function uses nmap to scan the network to map devices connected to the network. By default we use the most
common local IP range and all available ports. The majority of the leg work here is done by nmap, which is required
for this function to operate. https://nmap.org/download.html"""


def perform_network_scan():
    def thread_scan():
        for i in scan_tree.get_children():
            scan_tree.delete(i)  # Clear the treeview
        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments='-sn')  # Scan the local network (You can change this IP value)
        for host in nm.all_hosts():
            # Insert each host into the treeview in the main thread
            scan_tree.after(0, lambda h=host: scan_tree.insert("", "end", values=(h, nm[h].hostname(), nm[h].state())))

    # Run the scan in a separate thread
    threading.Thread(target=thread_scan, daemon=True).start()


"""This function allows us to double click an item in the network scan tab to display additional information about the
device that is selected."""


def on_item_selected(event):
    selected_item = scan_tree.focus()  # Get the selected item
    if not selected_item:
        return  # Return if nothing is selected

    # Get item values
    item_values = scan_tree.item(selected_item, "values")
    ip_address = item_values[0]  # IP address is the first value

    # Fetch information about the device.
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_address, arguments='-sV')  # Example: Version detection
        scan_info = nm[ip_address].all_protocols()
    except KeyError:
        # In case there is nothing to display.
        scan_info = "No detailed info available"

    # Display detailed information in a message box
    messagebox.showinfo("Detailed Information", f"IP: {ip_address}\nInfo: {scan_info}")


"""This function is just our search function for the active connections tab, it allows us to search by IP and Port."""


def search():
    ip = ip_entry.get()
    port = port_entry.get()
    update_connections(ip, port if port.isdigit() else None)


#  This entire section is our GUI which is made through Tkinter
root = tk.Tk()
root.title("Network Information Analyzer")

# Active Connections tab
tab_control = ttk.Notebook(root)
tab1 = ttk.Frame(tab_control)
tab_control.add(tab1, text='Active Connections')
tab_control.pack(expand=1, fill='both')

# Search fields
ip_label = ttk.Label(tab1, text="IP:")
ip_label.pack(side=tk.LEFT, padx=(10, 2))
ip_entry = ttk.Entry(tab1)
ip_entry.pack(side=tk.LEFT, padx=(0, 10))

port_label = ttk.Label(tab1, text="Port:")
port_label.pack(side=tk.LEFT, padx=(10, 2))
port_entry = ttk.Entry(tab1)
port_entry.pack(side=tk.LEFT, padx=(0, 10))

search_button = ttk.Button(tab1, text="Search", command=search)
search_button.pack(side=tk.LEFT, padx=(10, 10))

columns = ('local_ip', 'local_port', 'remote_ip', 'status')
tree = ttk.Treeview(tab1, columns=columns, show='headings')

tree.heading('local_ip', text='Local IP')
tree.heading('local_port', text='Local Port')
tree.heading('remote_ip', text='Remote IP')
tree.heading('status', text='Status')

tree.pack(expand=True, fill='both')

# Tab 2: Network Scan
tab2 = ttk.Frame(tab_control)
tab_control.add(tab2, text='Network Scan')
scan_columns = ('ip', 'hostname', 'status')
scan_tree = ttk.Treeview(tab2, columns=scan_columns, show='headings')
scan_tree.heading('ip', text='IP')
scan_tree.heading('hostname', text='Hostname')
scan_tree.heading('status', text='Status')
scan_tree.grid(row=0, column=0, sticky='nsew')
scan_button = ttk.Button(tab2, text="Scan Network", command=perform_network_scan)
scan_button.grid(row=1, column=0, pady=10)
scan_tree.bind('<Double-1>', on_item_selected)

tab_control.pack(expand=1, fill='both')

#  Tab 3: Network Health
tab3 = ttk.Frame(tab_control)
tab_control.add(tab3, text='Network Health')
network_health_label = ttk.Label(tab3, text="Pinging Google to assess network health...", padding=10)
network_health_label.pack()

# Tab 4: Network Usage Visualization
tab4 = ttk.Frame(tab_control)
tab_control.add(tab4, text='Network Usage')
network_usage_label = ttk.Label(tab4, text="Monitoring Network Usage....", padding=10)
network_usage_label.pack()
upload_progress = ttk.Progressbar(tab4, orient="horizontal", length=200, mode="determinate")
upload_progress.pack(pady=(10, 0))
download_progress = ttk.Progressbar(tab4, orient="horizontal", length=200, mode="determinate")
download_progress.pack(pady=(10, 20))
upload_progress["maximum"] = MAX_SPEED
download_progress["maximum"] = MAX_SPEED
upload_label = tk.Label(tab4, text="Upload Speed:")
upload_label.pack(pady=(20, 0))
download_label = tk.Label(tab4, text="Download Speed:")
download_label.pack(pady=(10, 0))

update_connections()
update_network_health()
fetch_network_usage(dow=None)

# Run the application
root.mainloop()
