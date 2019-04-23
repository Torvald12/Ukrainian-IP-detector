import tkinter as tk
from tkinter import *
from tkinter.filedialog import askopenfilename
from pcapfile import savefile
from ast import literal_eval
from time import gmtime, strftime
from ipaddress import ip_address
import urllib, urllib.request, os, ssl, threading, time, csv, ipaddress, zipfile
from tkinter import messagebox as mb
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

ssl._create_default_https_context = ssl._create_unverified_context

class IpDetection:
    def __init__(self, root):
        root.resizable(width=False, height=False)
        root.title('Ukrainian IP detector v1.1')
        root.grid_rowconfigure(0, weight=2)

        # FRAMES
        self.choosing_file_frame = tk.Frame(root, relief=SUNKEN)
        self.choosing_file_frame.grid(row=0, column=0, columnspan=2)

        self.all_found_ip_frame = tk.Frame(root, relief=SUNKEN)
        self.all_found_ip_frame.grid(row=3, column=0)

        self.ukrainian_ip_frame = tk.Frame(root, relief=SUNKEN)
        self.ukrainian_ip_frame.grid(row=3, column=1)

        self.button_frame = tk.Frame(root, borderwidth=10)
        self.button_frame.grid(row=1, column=0, columnspan=2)

        self.update_database_frame = tk.Frame(root, borderwidth=10)
        self.update_database_frame.grid(row=2, column=0, columnspan=2)

        self.status_frame = tk.Frame(root, borderwidth=10)
        self.status_frame.grid(row=4, column=0, columnspan=2)

        # CHOSING FILE
        self.choosing_file_label = Label(self.choosing_file_frame,
                                    text="Open a file with traffic to find Ukrainian IP addresses",
                                    font='TimesNewRoman 20')
        self.choosing_file_label.pack()

        self.choosing_file_entry = Entry(self.choosing_file_frame, font='TimesNewRoman 14', width=50, borderwidth=2)
        self.choosing_file_entry.pack(side=LEFT)

        self.choosing_file_button = Button(self.choosing_file_frame, text="Open file", fg="blue", width=8, height=1,
                                      font='TimesNewRoman 10', relief=RIDGE, command=lambda: threading.Thread(target=self.load_file).start())
        self.choosing_file_button.pack(side=LEFT)

        # BUTTON AND TIME
        r_var = tk.IntVar()
        r_var.set(0)
        self.find_ip_button = Button(self.button_frame, text="Find IPs", fg="green", width=8, height=2, font='TimesNewRoman 20',
                                     relief=RIDGE, command=lambda: threading.Thread(target=self.mainProcessing(r_var)).start())
        self.find_ip_button.pack(side=TOP)

        self.radiobutton_api = Radiobutton(self.button_frame, text="API", value=1, font='TimesNewRoman 14', variable=r_var)
        self.radiobutton_database = Radiobutton(self.button_frame, text="Database", value=2, font='TimesNewRoman 14', variable=r_var)
        self.radiobutton_api.pack(anchor=W)
        self.radiobutton_database.pack(anchor=W)

        self.find_ip_button = Button(self.update_database_frame, text="Update Database", fg="blue", width=15, height=1,
                                     font='TimesNewRoman 14',
                                     relief=RIDGE, command=lambda: threading.Thread(target=self.checkDatabaseActuality).start())
        self.find_ip_button.pack(side=TOP)

        self.update_time_entry = Entry(self.update_database_frame, font='TimesNewRoman 14', width=25, borderwidth=1, justify=CENTER)

        self.update_time_entry.insert(END, "Last update: " + str(open('database_status.txt').read()))
        self.update_time_entry.configure(state='disabled')
        self.update_time_entry.pack(side=RIGHT)

        self.time_label = Label(self.button_frame, text='Processing time: ', font='TimesNewRoman 14', borderwidth=10)
        self.time_label.pack(side=LEFT)

        self.time_entry = Entry(self.button_frame, font='TimesNewRoman 14', width=7)
        self.time_entry.pack(side=LEFT)
        self.time_entry.delete(0, END)
        self.time_entry.insert(END, '00:00:00')

        # ALL FOUND IP ADDRESSES
        self.all_found_ip_label = Label(self.all_found_ip_frame, text='All IP addresses: ', font='TimesNewRoman 14')
        self.all_found_ip_label.pack()

        self.all_found_ip_scrollbar = Scrollbar(self.all_found_ip_frame, orient=VERTICAL)
        self.all_found_ip_listbox = Listbox(self.all_found_ip_frame, yscrollcommand=self.all_found_ip_scrollbar.set,
                                       font='TimesNewRoman 14')
        self.all_found_ip_listbox.config(width=25)
        self.all_found_ip_listbox.pack()
        self.all_found_ip_scrollbar.config(command=self.all_found_ip_listbox.yview)
        self.all_found_ip_scrollbar.pack(side=RIGHT, fill=Y)
        self.all_found_ip_listbox.pack(side=LEFT, fill=BOTH, expand=1)

        # UKRAINIAN IP ADDRESSES
        self.ukrainian_ip_label = Label(self.ukrainian_ip_frame, text="Ukrainian IP addresses: ", font='TimesNewRoman 14')
        self.ukrainian_ip_label.pack()

        self.ukrainian_ip_scrollbar = Scrollbar(self.ukrainian_ip_frame, orient=VERTICAL)
        self.ukrainian_ip_listbox = Listbox(self.ukrainian_ip_frame, yscrollcommand=self.ukrainian_ip_scrollbar.set,
                                       font='TimesNewRoman 14')
        self.ukrainian_ip_listbox.config(width=25)
        self.ukrainian_ip_listbox.pack()
        self.ukrainian_ip_scrollbar.config(command=self.ukrainian_ip_listbox.yview)
        self.ukrainian_ip_scrollbar.pack(side=RIGHT, fill=Y)
        self.ukrainian_ip_listbox.pack(side=LEFT, fill=BOTH, expand=1)

        # STATUS PANNEL
        self.status_label = Label(self.status_frame, text="Status:", font='TimesNewRoman 20')
        self.status_label.pack()

        self.status_entry = Entry(self.status_frame, font='TimesNewRoman 12', width=86, justify=CENTER)
        self.status_entry.insert(END, "Please choose a file with traffic *.pcap")
        self.status_entry.configure(state='disabled')
        self.status_entry.pack(side=LEFT)

    def checkDatabaseActuality(self):
        self.status_changing("Checking the state of the Database. Please wait...")
        ua = dict(DesiredCapabilities.CHROME)
        options = webdriver.ChromeOptions()
        options.add_argument('headless')
        options.add_argument('window-size=1920x935')
        driver = webdriver.Chrome(chrome_options=options)
        driver.get("https://lite.ip2location.com/database/ip-country-region-city")
        time.sleep(3)
        actual_date = driver.find_element_by_xpath(
            '/html/body/div[3]/div/div/div/div/div/div[2]/div/div/div[3]/div[2]/div/table/tbody/tr[2]/td[2]')
        update_date = actual_date.text
        if open('database_status.txt').read() != update_date or os.path.exists('UKR-IPS-DATABASE.csv') == False:
            self.status_changing("The Database is being updated. Please wait...")
            self.downloadNewDatabase()
            open('database_status.txt', 'w').write(update_date)
            self.update_time_entry.configure(state='normal')
            self.update_time_entry.delete(0, END)
            self.update_time_entry.insert(END, "Last update: " + str(open('database_status.txt').read()))
            self.update_time_entry.configure(state='disabled')
            time.sleep(6)
            self.status_changing("Please choose a file with traffic *.pcap")
        else:
            self.status_changing("The Database is still actual. No need to update.")
            mb.showinfo("Actuality", "The Database is still actual")
            time.sleep(6)
            self.status_changing("Please choose a file with traffic *.pcap")

    def downloadNewDatabase(self):
        urllib.request.urlretrieve(
            'http://www.ip2location.com/download/?token=PbRZryBMBehO5OtJcS8QCx2xN0UYB8vrknqMV1yxgQmlEP4RIdIkKKRyKMwmV2Og&file=DB3LITE',
            'IP2LOCATION-LITE-DB3.CSV.zip')
        with zipfile.ZipFile('IP2LOCATION-LITE-DB3.CSV.zip', 'r') as zip_ref:
            zip_ref.extractall()
        os.remove('IP2LOCATION-LITE-DB3.CSV.zip')
        self.makeUkrDatabase()

    def makeUkrDatabase(self):
        if os.path.exists('UKR-IPS-DATABASE.csv') == True:
            os.remove('UKR-IPS-DATABASE.csv')
        with open('IP2LOCATION-LITE-DB3.csv') as File:
            reader = csv.reader(File, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            for row in reader:
                if (row[2]) == 'UA':
                    with open('UKR-IPS-DATABASE.csv', "a", newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4]), str(row[5])])
        os.remove('IP2LOCATION-LITE-DB3.csv')
        self.status_changing("The Database has been updated.")
        mb.showinfo("Actuality", "The Database has been updated successfully")


    def detectUkrainianIpApi(self, list_ip):
        self.time_entry.delete(0, END)
        self.time_entry.insert(END, '00:00:00')
        found_ip_addresses = list_ip
        f = 0
        while f < len(found_ip_addresses):
            self.all_found_ip_listbox.insert(END, found_ip_addresses[f])
            f += 1

        p = 0
        all_file_name = 'All_found_IPs_' + strftime("%Y-%m-%d_%H-%M-%S", gmtime()) + '.csv'
        while p < len(found_ip_addresses):
            with open(all_file_name, "a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([str(found_ip_addresses[p])])
            p += 1

        ukr_file_name = 'Ukrainian_IPs_' + strftime("%Y-%m-%d_%H-%M-%S", gmtime()) + '.csv'
        with open(ukr_file_name, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(['IP address', 'City', 'Region'])
        i = 0
        while i < len(found_ip_addresses):
            url_ipgeolocation = 'http://api.ipinfodb.com/v3/ip-city/?key=2e711472c2f3022b796d0ca7d29496521a949d3e96d24576be25f7dcac18fd5e&format=json&ip=' + found_ip_addresses[i]
            try:
                response = urllib.request.Request(url_ipgeolocation)
                data = literal_eval(urllib.request.urlopen(response).read().decode('utf8'))
            except urllib.error.HTTPError as err:
                if err.code == 423:
                    print('IP address ' + found_ip_addresses[i] + ' is a reserved IP address (private, multicast, etc.)')
                else:
                    print('ERROR ' + str(err.code))
            if data.get('countryName') == 'Ukraine':
                self.ukrainian_ip_listbox.insert(END, found_ip_addresses[i])
                with open(ukr_file_name, "a", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow([data.get('ipAddress'), str(data.get('cityName')), str(data.get('regionName'))])
            i += 1
            time.sleep(0.6)
        self.status_changing("Process finished. Found Ukr IPs have been saved to " + ukr_file_name)
        mb.showinfo("Process finished", "Ukrainian IPs have been found.")

    def detectUkrainianIpDatabase(self, list_ip):
        self.time_entry.delete(0, END)
        self.time_entry.insert(END, '00:00:00')
        found_ip_addresses = list_ip
        f = 0
        while f < len(found_ip_addresses):
            self.all_found_ip_listbox.insert(END, found_ip_addresses[f])
            f += 1

        p = 0
        all_file_name = 'All_found_IPs_' + strftime("%Y-%m-%d_%H-%M-%S", gmtime()) + '.csv'
        while p < len(found_ip_addresses):
            with open(all_file_name, "a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([str(found_ip_addresses[p])])
            p += 1

        ukr_file_name = 'Ukrainian_IPs_' + strftime("%Y-%m-%d_%H-%M-%S", gmtime()) + '.csv'
        with open(ukr_file_name, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(['IP address', 'City', 'Region'])
        i = 0
        while i < len(found_ip_addresses):
            with open('UKR-IPS-DATABASE.csv') as File:
                reader = csv.reader(File, delimiter=',', quotechar=',', quoting=csv.QUOTE_MINIMAL)
                for row in reader:
                    netaddr, broadcast = map(ip_address, [ipaddress.ip_address(int(row[0])).__str__(),
                                                          ipaddress.ip_address(int(row[1])).__str__()])
                    if (netaddr <= ip_address(found_ip_addresses[i]) <= broadcast) == True:
                        self.ukrainian_ip_listbox.insert(END, found_ip_addresses[i])
                        with open(ukr_file_name, "a", newline="") as file:
                            writer = csv.writer(file)
                            writer.writerow([found_ip_addresses[i], str(row[5]), str(row[4])])
            i += 1
        self.status_changing("Process finished. Found Ukr IPs have been saved to " + ukr_file_name)
        mb.showinfo("Process finished", "Ukrainian IPs have been found.")

    def mainProcessing(self, var):
        self.var = var
        self.all_found_ip_listbox.delete(0, END)
        self.ukrainian_ip_listbox.delete(0, END)
        traffic_file = self.choosing_file_entry.get()
        if len(traffic_file) != 0:
            testcap = open(traffic_file, 'rb')
            capfile = savefile.load_savefile(testcap, layers=2, verbose=True)
            start_time = time.time()
            list_with_ip = []
            i = 0
            while i < len(capfile.packets):
                list_with_ip.append(capfile.packets[i].packet.payload.src.decode("utf-8"))
                i += 1
            if len(list_with_ip) != 0:
                ip_list = list(set(list_with_ip))
                value = self.var.get()
                if value == 1:
                    self.detectUkrainianIpApi(ip_list)
                elif value == 2:
                    self.detectUkrainianIpDatabase(ip_list)
                elapsed_time = time.time() - start_time
                processing_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
                self.time_entry.delete(0, END)
                self.time_entry.insert(END, processing_time)
            else:
                self.status_changing('IP addresses haven`t been found.')
        else:
            self.status_changing('Choose a file please.')
            self.all_found_ip_listbox.delete(0, END)
            self.ukrainian_ip_listbox.delete(0, END)

    def load_file(self):
        file_name = askopenfilename(filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*")))
        self.choosing_file_entry.delete(0, END)
        self.choosing_file_entry.insert(0, file_name)

        self.all_found_ip_listbox.delete(0, 'end')
        self.ukrainian_ip_listbox.delete(0, 'end')

    def status_changing(self, status_text):
        self.status_entry.configure(state='normal')
        self.status_entry.delete(0, END)
        self.status_entry.insert(END, str(status_text))
        self.status_entry.configure(state='disabled')

class MainStream:
    def __call__(self):
        root = tk.Tk()
        root.iconbitmap('icon.ico')
        obj = IpDetection(root)  # object instantiated
        root.mainloop()

if __name__ == '__main__':
    main_stream = MainStream()
    thread_main = threading.Thread(target=main_stream)
    thread_main.start()
    thread_main.join()