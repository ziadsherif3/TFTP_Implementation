# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import struct

class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.

    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.

    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.

    This class is also responsible for reading/writing files to the
    hard disk.

    Failing to comply with those requirements will invalidate
    your submission.

    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5


    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.

        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        pass

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # add the packet to be sent to self.packet_buffer

        #packet_data and packet_source will be output of
        #socket.recvfrom()

        print(f"Received a packet from {packet_source}")

        in_packet = self._parse_udp_packet(packet_data) #Checks if RRQ or WRQ

        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """

        """
           2 bytes    string   1 byte     string   1 byte
               -----------------------------------------------
        RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
        WRQ    -----------------------------------------------
        """
        # Extract the first 2 bytes from packet
        opcode = struct.unpack("!H",packet_bytes[0:2])

        #Extract file name

        # Note : i'm not sure yet if i have to use unpack here
        # and in mode
        # I think yes lol :D

        fname = ""
        for x in range(2,len(packet_bytes)):
            if packet_bytes[x] == 0: #if reached termination char
                break
            else:
                fname += packet_bytes[x]

        '''Should i use this after the loop?'''
        #file_name = struct.unpack("!%ds"%len(fname),fname)

        #Extract mode
        mode = packet_bytes[x+1 : len(packet_bytes)-1]
        
        #mode_ = struct.unpack("!%ds"%len(mode), mode)


        if opcode == TftpProcessor.TftpPacketType.RRQ: #Read Request == 1
            pass

        elif opcode == TftpProcessor.TftpPacketType.WRQ: #Write Request == 2
            pass

        else :
            print("Invalid Packet!")

        pass

#
    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        pass

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.

        For example;
        s_socket.send(tftp_processor.get_next_output_packet())

        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.

        Leave this function as is.
        """
        return len(self.packet_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass

#DONE
def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.

    Feel free to delete this function.
    """
    # don't forget, the server's port is 69
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #Creating UDP socket
    sock.bind((address,69)) #Associate socket with a port to receive mesasages
    print(f"TFTP server started on on [{address}]...")
    return sock


def do_socket_logic(sock):
    '''This function will accept a socket as parameter
        and do the stuff'''
    pass


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    sock = setup_sockets(ip_address)

    #Socket Logic
    while True:
        print("Waiting to receive data...")
        data , addr = sock.recvfrom(2048)
        input_packet = TftpProcessor()

        input_packet.process_udp_packet(data,addr) #This Should do a lot of stuff :)


if __name__ == "__main__":
    main()