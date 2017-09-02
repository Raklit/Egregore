# /usr/bin/env python3.6

import traceback
import sys
try:
    import tkinter as tk
    from tkinter import messagebox as tkMessageBox
    from tkinter import ttk
    import EgregoreSocket as ctrls
    import threading as thr
    import os
    import time
    import gc
except:
    print('GUI class level error: you have not some libraries.')
    traceback.print_exc()
    i = input("Press enter to exit.")
    del i
    sys.exit(1)
else:
    print('GUI class level: All libraries was installed.')
    

#GUI's class

class GraphicalShell:
    #GUI's elements

    #panels
    
    root = None
    
    notebook_frame = None
    notebook = None

    main_panel = None
    settings_panel = None
    help_panel = None
    license_panel = None

    #main panel elements
    
    conn_info_frame = None
    conn_addr_area = None
    my_port_area = None
    
    msg_history_frame = None
    msg_history_area = None
    msg_history_scroll = None

    msg_send_frame = None
    msg_send_area = None
    msg_send_scroll = None

    button_frame = None
    send_button = None
    save_msg_button = None
    clear_msg_button = None
    socket_button = None
    try_to_connect_button = None
    wait_for_connection_button = None
    break_the_connection_button = None

    #settings panel elements

    my_key_len_frame = None
    my_first_RSA_key_len_area = None
    my_second_RSA_key_len_area = None

    settings_button_frame = None
    accept_settings_button = None
    reset_settings_button = None
    default_settings_button = None

    #help panel elements

    help_frame = None
    help_area = None
    help_scroll = None

    #license panel elements

    license_frame = None
    license_area = None
    license_scroll = None
    
    #basic
    
    label = list()

    #control elements
    
    EgregoreSocket = ctrls.EgregoreSocket()
    reader = None
    waiting_thread = None
    connection_thread = None

    #create GUI
    
    def __init__(self):
        #creating of elements
        self.root = tk.Tk()
        self.root.title('Egregore Beta. Default GUI.')
        self.root.protocol('WM_DELETE_WINDOW', self.__interf_exit)

        self.notebook_frame = tk.Frame(self.root)
        self.notebook_frame.pack()

        self.notebook = ttk.Notebook(self.notebook_frame)

        self.main_panel = ttk.Frame(self.notebook)
        self.settings_panel = ttk.Frame(self.notebook)
        self.help_panel = ttk.Frame(self.notebook)
        self.license_panel = ttk.Frame(self.notebook)

        self.notebook.add(self.main_panel, text = 'Messages')
        self.notebook.add(self.settings_panel, text = 'Settings')
        self.notebook.add(self.help_panel, text = 'Help')
        self.notebook.add(self.license_panel, text = 'License')
        
        self.notebook.pack()
        
        #main panel generating
        
        self.conn_info_frame = tk.Frame(self.main_panel)
        self.conn_info_frame.pack()
        
        self.label.append(tk.Label(self.conn_info_frame, text = 'Connection address:'))
        self.label[0].pack(side = tk.LEFT)

        self.conn_addr_area = tk.Entry(self.conn_info_frame)
        self.conn_addr_area.pack(side = tk.LEFT)

        self.label.append(tk.Label(self.conn_info_frame, text = ' My port:'))
        self.label[1].pack(side = tk.LEFT)

        self.my_port_area = tk.Entry(self.conn_info_frame)
        self.my_port_area.pack()
        
        self.msg_history_frame = tk.Frame(self.main_panel)
        self.msg_history_frame.pack()

        self.label.append(tk.Label(self.msg_history_frame, text = 'Message history:', pady = 10))
        self.label[2].pack()

        self.msg_history_scroll = tk.Scrollbar(self.msg_history_frame)
        self.msg_history_scroll.delta(0, 10)
        self.msg_history_scroll.pack(side = tk.RIGHT, fill = tk.Y)

        self.msg_history_area = tk.Text(self.msg_history_frame, yscrollcommand=self.msg_history_scroll.set, height=14, state=tk.DISABLED, wrap=tk.WORD)
        self.msg_history_area.pack()

        self.msg_send_frame = tk.Frame(self.main_panel)
        self.msg_send_frame.pack()

        self.label.append(tk.Label(self.msg_send_frame, text = 'Input your message:', pady = 10))
        self.label[3].pack()

        self.msg_send_scroll = tk.Scrollbar(self.msg_send_frame)
        self.msg_send_scroll.pack(side = tk.RIGHT, fill = tk.Y)

        self.msg_send_area = tk.Text(self.msg_send_frame, yscrollcommand=self.msg_send_scroll.set, height=10, wrap=tk.WORD)
        self.msg_send_area.pack()

        self.button_frame = tk.Frame(self.main_panel)
        self.button_frame.pack(fill = tk.X)

        self.send_button = tk.Button(self.button_frame, text = 'Send message')
        self.send_button.configure(pady = 8)
        self.send_button.pack(fill = tk.X)

        self.save_msg_button = tk.Button(self.button_frame, text = 'Save message history')
        self.save_msg_button.configure(pady = 8)
        self.save_msg_button.pack(fill = tk.X)

        self.clear_msg_button = tk.Button(self.button_frame, text = 'Сlear message history')
        self.clear_msg_button.configure(pady = 8)
        self.clear_msg_button.pack(fill = tk.X)
        
        self.socket_button = tk.Button(self.button_frame, text = 'Bind a socket')
        self.socket_button.pack(side = tk.LEFT)

        self.try_to_connect_button = tk.Button(self.button_frame, text = 'Try to connect')
        self.try_to_connect_button.pack(side = tk.LEFT)

        self.wait_for_connection_button = tk.Button(self.button_frame, text = 'Wait for connection')
        self.wait_for_connection_button.pack(side = tk.LEFT)

        self.break_the_connection_button = tk.Button(self.button_frame, text = 'Break the connection')
        self.break_the_connection_button.pack(side = tk.LEFT)

        #tags for msg history area
        
        self.msg_history_area.tag_config('recv_msg', foreground = 'blue')
        self.msg_history_area.tag_config('user_msg', foreground = 'red')
        self.msg_history_area.tag_config('sys_msg', foreground = 'orange')

        #set commands on button clicks in main panel
        self.send_button.configure(command = self.__interf_send_click)
        self.save_msg_button.configure(command = self.__interf_save_history)
        self.clear_msg_button.configure(command = self.__interf_clear_history)

        self.socket_button.configure(command = self.__interf_bind_socket)
        self.try_to_connect_button.configure(command = self.__interf_try_to_connect)
        self.wait_for_connection_button.configure(command = self.__interf_wait_for_connection)
        self.break_the_connection_button.configure(command = self.__interf_break_the_connection)
        
        #settings panel generating

        self.my_key_len_frame = tk.Frame(self.settings_panel)
        
        self.label.append(tk.Label(self.my_key_len_frame, text = 'First RSA key len (bytes):'))
        self.label[4].pack(side = tk.LEFT)

        self.my_first_RSA_key_len_area = tk.Entry(self.my_key_len_frame, width=10)
        self.my_first_RSA_key_len_area.pack(side = tk.LEFT)
        
        self.label.append(tk.Label(self.my_key_len_frame, text = ' Second RSA key len (bytes):'))
        self.label[5].pack(sid = tk.LEFT)

        self.my_second_RSA_key_len_area = tk.Entry(self.my_key_len_frame, width=10)
        self.my_second_RSA_key_len_area.pack(side = tk.LEFT)

        self.my_key_len_frame.pack()

        self.settings_button_frame = tk.Frame(self.settings_panel)

        self.default_settings_button = tk.Button(self.settings_button_frame, text = 'Restore default settings')
        self.default_settings_button.pack(side = tk.RIGHT)
        
        self.reset_settings_button = tk.Button(self.settings_button_frame, text = 'Reset')
        self.reset_settings_button.pack(side = tk.RIGHT)

        self.accept_settings_button = tk.Button(self.settings_button_frame, text = 'Accept')
        self.accept_settings_button.pack(side = tk.RIGHT)

        self.settings_button_frame.pack(side = tk.BOTTOM, fill = tk.X)

        #set commands on button clicks in settings panel
        self.accept_settings_button.configure(command = self.__interf_accept_settings_click)
        self.reset_settings_button.configure(command = self.__interf_reset_settings_click)
        self.default_settings_button.configure(command = self.__interf_default_settings_click)

        #help panel generating
        self.help_frame = tk.Frame(self.help_panel)
        self.help_frame.pack()

        self.help_scroll = tk.Scrollbar(self.help_frame)
        self.help_scroll.delta(0, 10)
        self.help_scroll.pack(side = tk.RIGHT, fill = tk.Y)

        self.help_area = tk.Text(self.help_frame, yscrollcommand=self.help_scroll.set, wrap=tk.WORD, height=40)
        self.help_area.pack()

        #print help in help panel
        self.__interf_print_help()

        #license panel generating
        self.license_frame = tk.Frame(self.license_panel)
        self.license_frame.pack()

        self.license_scroll = tk.Scrollbar(self.license_frame)
        self.license_scroll.delta(0, 10)
        self.license_scroll.pack(side = tk.RIGHT, fill = tk.Y)

        self.license_area = tk.Text(self.license_frame, yscrollcommand=self.license_scroll.set, wrap=tk.WORD, height=40)
        self.license_area.insert(tk.END, 'Copyright (c) 2017 N.A. Blokhin\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.')
        self.license_area.configure(state = tk.DISABLED)
        self.license_area.pack()
        
        
        #initial start state of form
        self.__interf_connection_is_off()

        #initial threads
        self.waiting_thread = thr.Thread(target=self.__interf_full_accept)
        self.connection_thread = thr.Thread(target=self.__interf_full_connect)
        self.reader = thr.Thread(target = self.__reader_daemon)
        
    #reader/writer's module
    
    def __reader_daemon(self):
        buf = False
        while True:
            try:
                if self.EgregoreSocket.already_connect:
                    buf = True
                    msg = self.EgregoreSocket.recv()
                    if msg != b'':
                        msg = msg.decode('utf-8')
                        self.__interf_print_recv_msg(msg)
            except:
                if buf:
                    self.__interf_print_sys_msg('Message reader thread was stopped.')
                    break
                else:
                    pass
            finally:
                time.sleep(0.1)

    def start_reader(self):
        self.__interf_print_sys_msg('Message reader thread was started.')
        self.reader.start()

    #this method don't use, but it is usefull for testing
    def printer(self, msg):
        self.msg_history_area.configure(state = tk.NORMAL)
        self.msg_history_area.insert(tk.END, msg + '\n')
        self.msg_history_area.configure(state = tk.DISABLED)

    #prefix '__interf_' using for interface control methods

    #interface level methods

    #methods for printing messages in history message area
        
    def __interf_print_recv_msg(self, msg):
        self.msg_history_area.configure(state = tk.NORMAL)
        self.msg_history_area.insert(tk.END, str(self.EgregoreSocket.conn_addr) + ': ', 'recv_msg')
        self.msg_history_area.insert(tk.END, msg + '\n')
        self.msg_history_area.configure(state = tk.DISABLED)

    def __interf_print_user_msg(self, msg):
        self.msg_history_area.configure(state = tk.NORMAL)
        self.msg_history_area.insert(tk.END, 'I: ', 'user_msg')
        self.msg_history_area.insert(tk.END, msg + '\n')
        self.msg_history_area.configure(state = tk.DISABLED)

    def __interf_print_sys_msg(self, msg):
        self.msg_history_area.configure(state = tk.NORMAL)
        self.msg_history_area.insert(tk.END, 'System: ', 'sys_msg')
        self.msg_history_area.insert(tk.END, msg + '\n')
        self.msg_history_area.configure(state = tk.DISABLED)



    #methods for control content of conn info frame

    def __interf_block_conn_info(self):
        try:
            self.conn_addr_area.configure(state = tk.DISABLED)
            self.my_port_area.configure(state = tk.DISABLED)
        except:
            pass
        
    def __interf_unblock_conn_info(self):
        try:
            self.conn_addr_area.configure(state = tk.NORMAL)
            self.my_port_area.configure(state = tk.NORMAL)
        except:
            pass

    def __interf_print_conn_info(self):
        self.my_port_area.configure(state = tk.NORMAL)
        self.my_port_area.delete(0, tk.END)
        self.my_port_area.insert(tk.END, str(self.EgregoreSocket.my_port))

        self.conn_addr_area.configure(state = tk.NORMAL)
        self.conn_addr_area.delete(0, tk.END)
        self.conn_addr_area.insert(tk.END, self.EgregoreSocket.conn_addr[0] + ':' + str(self.EgregoreSocket.conn_addr[1]))

    #methods for control button state in form

    def __interf_button_state_for_connected_state(self):
        self.send_button.configure(state = tk.NORMAL)
        self.break_the_connection_button.configure(state = tk.NORMAL)

        self.socket_button.configure(state = tk.DISABLED)
        self.try_to_connect_button.configure(state = tk.DISABLED)
        self.wait_for_connection_button.configure(state = tk.DISABLED)
        
        self.accept_settings_button.configure(state = tk.DISABLED)
        self.reset_settings_button.configure(state = tk.DISABLED)
        self.default_settings_button.configure(state = tk.DISABLED)

    def __interf_button_state_for_nonconnected_state(self):
        self.send_button.configure(state = tk.DISABLED)
        self.break_the_connection_button.configure(state = tk.DISABLED)

        self.socket_button.configure(state = tk.NORMAL)
        self.try_to_connect_button.configure(state = tk.NORMAL)
        self.wait_for_connection_button.configure(state = tk.NORMAL)
        
        self.accept_settings_button.configure(state = tk.NORMAL)
        self.reset_settings_button.configure(state = tk.NORMAL)
        self.default_settings_button.configure(state = tk.NORMAL)

    #methods for control form text area state in form

    def __interf_textarea_state_for_connected_state(self):
        self.__interf_reset_settings_click()
        self.my_first_RSA_key_len_area.configure(state = tk.DISABLED)
        self.my_second_RSA_key_len_area.configure(state = tk.DISABLED)

    def __interf_textarea_state_for_nonconnected_state(self):
        self.my_first_RSA_key_len_area.configure(state = tk.NORMAL)
        self.my_second_RSA_key_len_area.configure(state = tk.NORMAL)
        
        
    #methods for control form state

    def __interf_connection_is_on(self):
        self.__interf_block_conn_info()
        self.__interf_button_state_for_connected_state()
        self.__interf_textarea_state_for_connected_state()

    def __interf_connection_is_off(self):
        self.__interf_unblock_conn_info()
        self.__interf_button_state_for_nonconnected_state()
        self.__interf_textarea_state_for_nonconnected_state()

    def __interf_connection_is_established(self):
        self.__interf_connection_is_on()
        self.send_button.configure(state = tk.DISABLED)
        self.break_the_connection_button.configure(state = tk.DISABLED)

    #methods for click button events in main panel
    
    def __interf_send_click(self):
        try:
            msg = self.msg_send_area.get("0.0", tk.END + "-1c")
            if msg != "":
                msg_bytes = msg.encode('utf-8')
                result = self.EgregoreSocket.send(msg_bytes)
                if result:
                    self.__interf_print_user_msg(msg)
                else:
                    self.__interf_print_sys_msg('Can not send the message. Try again or restart the connection.')
        except:
            self.__interf_print_sys_msg('Can not send the message. Try again or restart the connection.')
        else:
            self.msg_send_area.delete("0.0", tk.END)

    def __interf_save_history(self):
        try:
            #create log folder
            log_folder_name = 'Egregore_logs'
            if not os.path.exists(log_folder_name):
                os.mkdir(log_folder_name)
            #create and open log file
            log_prefix = 'Egregore_log_('
            log_postfix = ').txt'
            t = time.localtime(time.time())
            log_file_name = log_prefix +  time.strftime("%a_%d_%b_%Y_%Hh_%Mm_%Ss", t) + log_postfix
            current_file = open(os.path.join(log_folder_name, log_file_name), 'w')
            #insert log in file
            content = self.msg_history_area.get("0.0", tk.END)
            current_file.write(content)
            #close and save log file
            current_file.close()
        except:
            self.__interf_print_sys_msg('Can not save message history.')
        else:
            self.__interf_print_sys_msg('Message history was saved.')

    def __interf_clear_history(self):
        self.msg_history_area.configure(state = tk.NORMAL)
        self.msg_history_area.delete('0.0', tk.END)
        self.msg_history_area.configure(state = tk.DISABLED)
    
    def __interf_bind_socket(self):
        buf = self.my_port_area.get()
        if (buf == '' or not buf.isdigit()):
            port = 8196
        else:
            port = int(self.my_port_area.get())
            
        result = self.EgregoreSocket.bind(port)
        if (result):
            self.__interf_print_sys_msg('Port ' + str(port) + ': Socket bind successfully completed.')
        else:
            self.__interf_print_sys_msg('Port ' +  str(port) + ': Socket bind failed (already used by other process or blocked by OS).\nPlease, try other port, close other process or reboot computer.')

        del buf
        del result
        del port
        gc.collect()

    #start connect module

    def __interf_wait_for_connection(self):
        if (not self.EgregoreSocket.already_connect):
            self.waiting_thread.start()
            self.__interf_connection_is_established()
            while (True):
                try:
                    self.waiting_thread.join(0.5)
                except:
                    continue
                else:
                    break
                finally:
                    del self.waiting_thread
                    self.waiting_thread = thr.Thread(target=self.__interf_full_accept)
                    self.reader = thr.Thread(target = self.__reader_daemon)
                    gc.collect()
        else:
            self.__interf_print_sys_msg('You are already connected.')
    
    def __interf_full_accept(self):
        if self.EgregoreSocket.pre_accept():
            text = "Do you want to start talking with " +  str(self.EgregoreSocket.conn_addr) + "?"
            self.__interf_print_sys_msg('A possible connection was started.')
            self.EgregoreSocket.signal = tkMessageBox.askyesno("Egregore Beta. Default GUI.", text)
            result = self.EgregoreSocket.full_accept()
            if result:
                self.__interf_print_conn_info()
                self.__interf_connection_is_on()
                self.start_reader()
                self.__interf_print_sys_msg('The connection was started.')
                return True
            else:
                self.EgregoreSocket = ctrls.EgregoreSocket()
                self.__interf_connection_is_off()
                self.__interf_print_sys_msg('The connection was not established.')
                return False
        else:
            self.EgregoreSocket = ctrls.EgregoreSocket()
            self.__interf_connection_is_off()
            return False

    def __interf_try_to_connect(self):
        if (not self.EgregoreSocket.already_connect):
            self.connection_thread.start()
            self.__interf_connection_is_established()
            while (True):
                try:
                    self.connection_thread.join(0.5)
                except:
                    continue
                else:
                    break
                finally:
                    del self.connection_thread
                    self.connection_thread = thr.Thread(target=self.__interf_full_connect)
                    self.reader = thr.Thread(target = self.__reader_daemon)
                    gc.collect()
        else:
            self.__interf_print_sys_msg('You are already connected.')
    
    def __interf_full_connect(self):
        try:
            full_addr = self.conn_addr_area.get()
            full_addr = full_addr.split(':')
            addr = full_addr[0]
            port = int(full_addr[1])
            result = self.EgregoreSocket.full_connect(addr, port)
            if result:
                self.__interf_print_conn_info()
                self.__interf_connection_is_on()
                self.start_reader()
                self.__interf_print_sys_msg('The connection was started.')
                return True
            else:
                self.EgregoreSocket = ctrls.EgregoreSocket()
                self.__interf_connection_is_off()
                self.__interf_print_sys_msg('The connection was not established.')
                return False
        except:
            self.__interf_print_sys_msg('Something is wrong. Check connectinon address or rebind socket.')
            self.__interf_connection_is_off()


    def __interf_break_the_connection(self):
        self.EgregoreSocket.close()
        self.EgregoreSocket = ctrls.EgregoreSocket()
        self.__interf_connection_is_off()
        self.__interf_print_sys_msg("Socket was destroyed.")
        gc.collect()

    #methods for click button events in settings panel
    
    def __interf_accept_settings_click(self):
        str_first_RSA_len = self.my_first_RSA_key_len_area.get()
        str_second_RSA_len = self.my_second__key_len_area.get()
        if (str_first_RSA_len.isdigit() and str_second_RSA_len.isdigit()):
            try:
                num_first_RSA_len = int(str_first_RSA_len)
                num_second_RSA_len = int(str_second_RSA_len)
            except:
                self.__interf_key_len_error()
            else:
                if (num_first_RSA_len % 16 == 0 and num_second_RSA_len % 16 == 0 and num_first_RSA_len >= 4096 and num_second_RSA_len >= 4096):
                    self.EgregoreSocket.my_first_RSA_key_len = num_first_RSA_len
                    self.EgregoreSocket.my_second_RSA_key_len = num_second_RSA_len
                else:
                    self.__interf_key_len_error()
        else:
            self.__interf_key_len_error()

    def __interf_key_len_error(self):
        text = 'Key len error. Key len must be:\nRSA key len >= 4096.\nRSA key len mod 16 = 0.\nPlease, try to input another data.'
        tkMessageBox.showerror('Egregore Beta. Default GUI.', text)
        del text
        gc.collect()
    
    def __interf_reset_settings_click(self):
        self.my_first_RSA_key_len_area.configure(state = tk.NORMAL)
        self.my_first_RSA_key_len_area.delete(0, tk.END)
        self.my_first_RSA_key_len_area.insert(tk.END, str(self.EgregoreSocket.my_first_RSA_key_len))

        self.my_second_RSA_key_len_area.configure(state = tk.NORMAL)
        self.my_second_RSA_key_len_area.delete(0, tk.END)
        self.my_second_RSA_key_len_area.insert(tk.END, str(self.EgregoreSocket.my_second_RSA_key_len))

    def __interf_default_settings_click(self):
        self.my_first_RSA_key_len_area.configure(state=tk.NORMAL)
        self.my_first_RSA_key_len_area.delete(0, tk.END)
        self.my_first_RSA_key_len_area.insert(tk.END, '4096')
        
        self.my_second_RSA_key_len_area.configure(state=tk.NORMAL)
        self.my_second_RSA_key_len_area.delete(0, tk.END)
        self.my_second_RSA_key_len_area.insert(tk.END, '4096')

        self.__interf_accept_settings_click()


    #print help from file
    def __interf_print_help(self):
        self.help_area.configure(state = tk.NORMAL)
        self.help_area.delete('0.0', tk.END)
        try:
            f = open('help.txt', 'r')
            self.help_area.insert(tk.END, str(f.read()))
            f.close()
        except:
            self.help_area.insert(tk.END, 'Help file can not be printed. Oops...')
        else:
            pass
        finally:
            self.help_area.configure(state = tk.DISABLED)
            f = None
            gc.collect()
            
    #onExit event
    def __interf_exit(self):
         self.EgregoreSocket.close()
         self.root.destroy()
         gc.collect()
    
#main thread code

def main():
    interface = GraphicalShell()
    interface.root.mainloop()
    os._exit(0)

if __name__ == '__main__':
    main()
