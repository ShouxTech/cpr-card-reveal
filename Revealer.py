from dearpygui.core import *
from dearpygui.simple import *
from threading import Thread
import event_emitter as events
from scapy.all import sniff

class Interface:
    def __init__(self):
        set_main_window_size(400, 400)
        set_global_font_scale(1.2)

        with window('Card Jitsu - Card Revealer', width = 400, height = 400):
            set_window_pos('Card Jitsu - Card Revealer', 0, 0)
            add_text('Not Connected', color = [180, 0, 0])
            add_spacing(count = 2)
            add_drawing('Card', width = 400, height = 400)

        draw_image('Card', './cards/1.png', pmin = [0, 0], pmax = [250, 280], tag = 'image')

        Thread(target = start_dearpygui).start()

    def connected(self):
        hide_item('Not Connected')

    def change_image(self, ID):
        draw_image('Card', './cards/{}.png'.format(str(ID)), pmin = [0, 0], pmax = [250, 280], tag = 'image')

class ReceivePacket(events.EventEmitter):
    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.connected = False

    def start(self):
        def receive_packet(packet):
            packet_data = str(packet.load)
            tcp_packet_data_start = packet_data.find('%xt')
            if tcp_packet_data_start != -1 and (not self.connected):
                self.connected = True
                self.interface.connected()
            if (packet_data.find('%jr%') != -1) or (packet_data.find('%jz%') != -1) or (packet_data.find('%zm%') != -1):
                self.emit('packet', packet_data)

        sniff(filter = 'tcp and src 85.217.222.71', prn = receive_packet)

class Revealer():
    def __init__(self):
        self.interface = Interface()

        self.cards = {} # Collected card's from game start-up
        self.collected = False # Check if inventory card's on game start-up are collected
        self.invID = None # Inventory ID of opponents most recent selected card
        self.side = None # If penguin's on left or right

        receive_packet = ReceivePacket(self.interface)
        receive_packet.on('packet', self.read_packet)
        receive_packet.start()

    def get_cards(self, packet):
        deconstructed = packet.split('|')

        self.cards = { # ID of first card, second card, etc...
            0: deconstructed[1],
            1: deconstructed[6],
            2: deconstructed[11],
            3: deconstructed[16],
            4: deconstructed[21]
        }

        self.collected = True

        return self.cards

    def handle_deal(self, packet):
        newCard = packet.split('|')
        inventoryNum = int(newCard[0])
        cardID = newCard[1]

        del self.cards[self.invID]

        self.cards[inventoryNum] = cardID

    def handle_zm(self, packet, deconstructed_packet):
        action = deconstructed_packet[4] # Deal/Judge/Pick
        side = deconstructed_packet[5] # The penguin's side that the packet came from
        if (side == self.side) or (action == 'judge'):
            return

        if not self.collected:
            self.cards = self.get_cards(packet)
        elif action == 'pick':
            invID = int(deconstructed_packet[6]) # The inventory ID of opponent's selected card
            self.invID = invID
            self.interface.change_image(self.cards[invID])
            #print('https://raw.githubusercontent.com/akbenjii/cpr-card-reveal/main/src/cards/{}.png'.format(self.cards[invID]))
        elif action == 'deal':
            self.handle_deal(deconstructed_packet[6])

    def reset(self):
        self.cards = []
        self.collected = False
        self.invID = None
        self.side = None

    def read_packet(self, packet):
        deconstructed_packet = packet.split('%')
        if packet.find('%jz%') != -1:
            self.side = deconstructed_packet[4] # Determine side of penguin, 0 on left, 1 on right
        elif packet.find('%zm%') != -1:
            self.handle_zm(packet, deconstructed_packet)
        elif packet.find('%jr%') != -1:
            self.reset()

Revealer()
