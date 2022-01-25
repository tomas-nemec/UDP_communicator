import math
import socket
import struct
import threading
import time
import os
import binascii

# program was written by Tomas Nemec
# 2021

HEADER_SIZE = 3


def keep_alive(client_s, server_address):
    while(True):
        time.sleep(0.1)
        global stop_THREAD
        if stop_THREAD:
            client_s.settimeout(None)
            print("KEEP-ALIVE thread was KILLED")
            return
        else:
            KA_messag = struct.pack("=BH", 0, 0)
            client_s.sendto(KA_messag, server_address)  # sending KEEP-ALIVE message

            client_s.settimeout(10) # wait if get response in 10 seconds
            try:
                data, address = client_s.recvfrom(1500)
                type_header, crc_header = struct.unpack("=BH", data[:HEADER_SIZE])
                if (type_header == 0):
                    print("received KEEP-ALIVE")
            except socket.timeout:
                print("NOT received KEEP-ALIVE")
            time.sleep(5)

def establish_server():
    server_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create socket (IPv4 and UDP procol)
    host_name = socket.gethostbyname(socket.gethostname())      # get own IP address
    while(True):
        port = int(input("Enter server port(1024-65353): "))
        if(port >= 1024 and port <= 65353):
            try:
                server_s.bind((host_name, port))  # bind the port
                break
            except:
                print("This PORT is already opened")


    print("\nIP: " + str(host_name))
    print("Port: " + str(port))
    print("=========== SERVER READY ==============\n")
    server(server_s)

def establish_client():
    client_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create client socket
    while(True):
        port = int(input("Enter port of the server(1024-65353): "))
        if (port >= 1024 and port <= 65353):
            break
    server_name = input("Enter IP address of server: ")

    server_address = (server_name, port)    # endpoint
    fragment_size = int()
    while (True):
        fragment_size = int(input("Size of fragment(5-1465): ")) # 1500 - UDP(8) - my_header(3) - IPv4(20) - NULL-lpback(4)
        if (fragment_size >= 5 and fragment_size < 1465):
            break

    client(client_s, server_address, fragment_size)


"""     SOCKETS exist       """

def client(client_s, server_address, fragment_size):
    # establish connection with own 2-way handshake
    establish_connection(client_s, server_address)

    global stop_THREAD  # globalna variable for KEEP-ALIVE function
    max_size_of_fragment = fragment_size
    while(True):
        # THREAD for keep-alive
        stop_THREAD = False
        KA_thread = threading.Thread(target=keep_alive, args=(client_s, server_address))
        KA_thread.start()

        print("0 - change configuration")
        print("1 - send messages")
        print("2 - send file")
        print("3 - switch users")
        print("4 - exit")
        input1 = input("Command: ")

        if(input1 == "0"):  # change max size of fragment
            stop_THREAD = True  # shut down keep alive thread
            KA_thread.join()
            while (True):
                f_s = int(input("New size of fragment(5-1465): "))
                if (f_s >= 5 and f_s < 1465):
                    max_size_of_fragment = f_s
                    break

        elif(input1 == "1"):    # sending of txt message
            stop_THREAD = True
            KA_thread.join()
            while (True):
                message_to_send = input("Message to send: ")
                if (message_to_send == "exit"):
                    break
                # send message to server
                send(client_s, server_address, "txt", max_size_of_fragment, message_to_send, False)


                while(True):    # after message was sent, client is waiting for response from server
                    data, address = client_s.recvfrom(1500)
                    type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])
                    if(type_h == 6):    # first initial packet, says how many packets will be received
                        num_of_fragments = int(data[HEADER_SIZE:].decode("utf-8"))
                        if (num_of_fragments > 0):
                            print(receive(num_of_fragments, client_s, "message"))
                            break
                        if (num_of_fragments == 0):
                            print("no response to message from SERVER")
                            break
                    elif(type_h == 8):  # initialize switch between client and server
                        client_s.close()
                        return


        elif (input1 == "2"):   # file will be sent
            stop_THREAD = True
            KA_thread.join()
            apply_mistakes = input("Include incorrect fragments?(y/n): ")   # include incorrect fragments which will be sent again?
            if (apply_mistakes == "y"):
                apply_mistakes = True
            else:
                apply_mistakes = False

            path_to_file = input("Enter full path to file: ")
            rest_of_path, name_of_file = os.path.split(path_to_file)    # get only name of file which will be sent

            file_obj = open(path_to_file, "rb") # read file in binary
            file_in_bytes = file_obj.read()

            send(client_s, server_address, "file", max_size_of_fragment, file_in_bytes, apply_mistakes) # send file
            send(client_s, server_address, "txt", max_size_of_fragment, name_of_file, False)    # send name of file

            print("Path to file: "+ str(path_to_file))
            print("Total size of file: " + str(len(file_in_bytes)) + " B")
            print("Number of fragments: " + str(math.ceil(len(file_in_bytes) / fragment_size)))

            data, address = client_s.recvfrom(1500) # opportunity for server to initialize change of roles
            type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])
            if(type_h == 2):
                continue
            elif(type_h == 8):  # exchange of roles was initialized
                client_s.close()
                return


        elif(input1 == "3"):    # initialize role exchange
            stop_THREAD = True
            KA_thread.join()
            client_s.sendto(struct.pack("=BH", 8, 0), server_address)  # send ACK
            client_s.close()
            return


        elif(input1 == "4"):    # exit
            stop_THREAD = True
            KA_thread.join()
            terminate_connection(client_s, server_address)
            client_s.close()
            break

def server(server_s):
    connection_established = 0

    while(True):
        server_s.settimeout(60)
        try:
            # waiting for SYN to estabilsh connectiom
            data, client_address = server_s.recvfrom(1500)
            type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])
            if (type_h == 1):  # prisiel SYN, posle ACK a spojenie mame zalozene
                server_s.sendto(struct.pack("=BH", 2, 0), client_address)  # poslem ACK
                print(f"Connection with {client_address} was established!")
                connection_established = 1
            # 2-way HANDSHAKE completed
        except (socket.timeout) as e:   # if server want establish a connection in 60s, will be closed
            print("\nServer was TERMINATED due to inactivity !!!\n")
            server_s.close()
            exit()



        while(connection_established):      # completed 2-way handshake, connection established

            server_s.settimeout(60)     # 60s without received message, server will be closed
            try:
                message, client_address = server_s.recvfrom(1500)
                header_type, header_crc = struct.unpack("=BH", message[:HEADER_SIZE])
                # get message, deal with it based on type of message
                if(header_type == 0):  # if type is keep_alive
                    print("received Keep-alive")
                    server_s.sendto(struct.pack("=BH", 0, 0), client_address)

                elif(header_type == 6):  # will be receiving TXT message
                    server_s.settimeout(None)
                    num_of_fragments = int(message[HEADER_SIZE:].decode("utf-8"))
                    print(receive(num_of_fragments, server_s, "message"))
                    aaa = input("Want to respond(y/n):")
                    if(aaa == "y"):
                        response_to_client = input("answer the client(switch - initialize switch):")
                        if(response_to_client == "switch"):
                            server_s.sendto(struct.pack("=BH", 8, 0), client_address)
                            server_s.close()
                            return

                        else:
                            send(server_s, client_address, "txt", 1500, response_to_client, False)
                    else:   # send message with 0 which means server wont respond to client
                        server_s.sendto(struct.pack("=BH", 6, 0) + str(0).encode("utf-8"), client_address)

                elif(header_type == 7):  # server will be receiving file
                    server_s.settimeout(None)
                    num_of_fragments = int(message[HEADER_SIZE:].decode("utf-8"))
                    file_in_bytes = receive(num_of_fragments, server_s, "file")  # get all bytes if file
                    file_name = ""
                    while(True):    # also need to receive a name of file
                        message, client_address = server_s.recvfrom(1500)
                        header_type, header_crc = struct.unpack("=BH", message[:HEADER_SIZE])
                        if(header_type == 6):   # will be receiving TXT message (name of file)
                            num_of_fragments = int(message[HEADER_SIZE:].decode("utf-8"))
                            file_name += receive(num_of_fragments, server_s, "message") # got name of file
                            break
                    what = create_file(file_name, file_in_bytes, server_s, client_address)

                    if(what == "exit"):
                        server_s.close()
                        return


                elif(header_type == 4): # got RST, connection terminated
                    server_s.sendto(struct.pack("=BH", 2, 0), client_address)   # send ACK to RST
                    print(f'Client {client_address} was disconnected !')
                    connection_established = 0
                    break

                elif(header_type == 8):
                    server_s.close()
                    return
            except (socket.timeout) as e:
                print("\nServer is TERMINATED due to inactivity !!!\n")
                server_s.close()
                exit()


"""     FUNKCIE SEND/RECEIVE        """

def receive(total_frags, server_s, what):   # funkcia na prijmanie sprav
    correct_fragments = 1
    all_fragments = 0
    message = ""
    file_fragments = []

    while(True):
        if((correct_fragments - 1) == total_frags):
            break

        data, address = server_s.recvfrom(1500)    # server is listening
        type_header, crc_header = struct.unpack("=BH",data[:HEADER_SIZE])   # after receiving packet, deal with header
        all_fragments += 1
        calculated_crc = binascii.crc_hqx(struct.pack("=B", type_header) + data[HEADER_SIZE:] , 0)

        if(crc_header == calculated_crc):      # if CRC is OK
            received_data = ""
            if(type_header == 3):   # if type of header is PUSH, receiving data
                if(what == "message"):  # if receiving TXT message
                    received_data = data[HEADER_SIZE:].decode("utf-8")
                    message += received_data
                else:   # if receiving file, append block into list
                    received_data = data[HEADER_SIZE:]
                    file_fragments.append(received_data)
                print(f"Packet n.{correct_fragments} => size: {len(received_data)} received correctly, sending ACK")
                correct_fragments += 1
                # send ACK about correct packet
                server_s.sendto(struct.pack("=BH", 2, 0), address)

        else:
            print(f"ERROR in packet n.{correct_fragments}, sending NACK")
            server_s.sendto(struct.pack("=BH", 5, 0), address)  # posle NACK


    if(what == "message"):
        return message


    elif(what == "file"):   # whole file is received
        return file_fragments

def send(client_s, server_address, what, fragment_size, spravicka, apply_mistakes): # function for TXT message sending
    message = ""
    total_number_of_fragments = 0
    correct_fragments = 0
    act_fragment_num = 1


    if(what == "txt"):  # sending TXT message
        message += spravicka
        size_of_message = len(message)
        number_of_fragments = math.ceil(size_of_message / fragment_size)

        # initial packet with number of fragments which will be sent
        client_s.sendto(struct.pack("=BH",6, binascii.crc_hqx(struct.pack("=B",6) + str(number_of_fragments).encode("utf-8"), 0) ) + str(number_of_fragments).encode("utf-8"), server_address)    # poslem uvodnu spravu s poctom fragmentov

        while(True):
            if(len(message) == 0):  # if all fragments are already sent
                break

            frag_to_send = message[:fragment_size]
            frag_to_send = frag_to_send.encode("utf-8")
            message = message[fragment_size:]
            crc_to_send = binascii.crc_hqx(struct.pack("=B",3) + frag_to_send, 0)

            header = struct.pack("=BH", 3, crc_to_send)  #PSH
            act_fragment_num += 1

            client_s.sendto(header + frag_to_send, server_address)
            total_number_of_fragments += 1
            # send packet and wait for ACK/NACK
            while(True):
                data, address = client_s.recvfrom(1500)
                type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])
                if(type_h == 2):    # ACK
                    correct_fragments += 1
                    break
                elif(type_h == 5):  # NACK
                    client_s.sendto(header + frag_to_send, server_address)
                    total_number_of_fragments += 1



    elif( what == "file"):
        message = spravicka
        size_of_file = len(message)
        number_of_fragments = math.ceil(size_of_file / fragment_size)

        # initial message with info that file will be sent
        client_s.sendto(struct.pack("=BH", 7, binascii.crc_hqx(struct.pack("=B", 7) + str(number_of_fragments).encode("utf-8"), 0)) + str(number_of_fragments).encode("utf-8"), server_address)  # poslem uvodnu spravu s poctom fragmentov

        while(True):
            if (len(message) == 0):
                break

            frag_to_send = message[:fragment_size]
            copy_frag_to_send = message[:fragment_size]
            message = message[fragment_size:]
            crc_to_send = binascii.crc_hqx(struct.pack("=B", 3) + frag_to_send, 0)

            if (apply_mistakes == True and act_fragment_num % 100 == 0):
                    frag_to_send = frag_to_send[1:]

            header = struct.pack("=BH", 3, crc_to_send)


            client_s.sendto(header + frag_to_send , server_address)
            while(True):
                data, address = client_s.recvfrom(1500)
                type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])

                if(type_h == 2):
                    break
                elif(type_h == 5):  # if NACK was received, send Packet again
                    crc_to_send = binascii.crc_hqx(struct.pack("=B", 3) + copy_frag_to_send, 0)
                    header = struct.pack("=BH", 3, crc_to_send)
                    client_s.sendto(header + copy_frag_to_send, server_address)

            act_fragment_num += 1

"""     CONNECTION / FILE creator"""
def establish_connection(client_s, server_address):
    # 2-way handshake
    client_s.sendto(struct.pack("=BH", 1, 0), server_address) # send SYN
    data1, address = client_s.recvfrom(1500)  # wait for response
    type_h1, crc_h1 = struct.unpack("=BH", data1[:HEADER_SIZE])
    if (type_h1 == 2):  # if received ACK, connection established
        print(f"Connected to the server {address} !")

def terminate_connection(client_s, server_address):
    client_s.sendto(struct.pack("=BH", 4, 0), server_address)   # send RST
    while (True):
        data, address = client_s.recvfrom(1500)
        type_h, crc_h = struct.unpack("=BH", data[:HEADER_SIZE])
        if (type_h == 2):
            print(f"Disconnected from the server: {address} !")
            break

def create_file(name, data, server_s, client_address): # function to put together file
    where_to_save = input("Path where to store file: ")
    f = open(where_to_save + name, "wb")
    num_frag = 0
    total_size = 0
    for i in data:
        total_size += len(i)
        num_frag += 1
        f.write(i)
    f.close()
    print("Location where file is stored: " + str(where_to_save) + str(name))
    print("Size of file: " + str(total_size + len(name)) + " B")
    print("Number of fragments: " + str(num_frag))
    next_step = input("Initialize switch?(y/n)")    # tu dam moznost serveru inicializovat vymenu
    if(next_step == "y"):
        server_s.sendto(struct.pack("=BH", 8, 0), client_address)
        return "exit"
    else:
        server_s.sendto(struct.pack("=BH", 2, 0), client_address)


while(True):
    a = int(input("1-server / 2-client / 3-exit\n"))
    if(a == 1):     # SERVER
        establish_server()
    elif(a == 2):   # CLIENT
        establish_client()
    elif (a == 3):  # exit
        exit()
