import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
import random

import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*

# --- START: Added for improved error handling and logging ---
# Configure logging to provide clear information about the bot's status and errors.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot_activity.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
# --- END: Added for improved error handling and logging ---


tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']
    
# Emote name to ID mapping - COMPLETE UPDATED VERSION
emote_map = {
    # Basic Emotes (1-150)
     # Simple Emote Name to ID Mapping
    # Evo Guns
    'p90': 909049010,
    'm60': 909051003,
    'mp5': 909033002,
    'groza': 909041005,
    'thompson_evo': 909038010,
    'm10_red': 909039011,
    'mp40_blue': 909040010,
    'm10_green': 909000081,
    'xm8': 909000085,
    'ak': 909000063,
    'mp40': 909000075,
    'm4a1': 909033001,
    'famas': 909000090,
    'scar': 909000068,
    'ump': 909000098,
    'm18': 909035007,
    'fist': 909037011,
    'g18': 909038012,
    'an94': 909035012,
    'woodpecker': 909042008,
    
    # Special Emotes
    'money': 909000055,
    'paisa': 909000055,
    'heart': 909000045,
    'love': 909000045,
    'rose': 909000010,
    'throne': 909000014,
    'pirate': 909000034,
    'flag': 909000034,
    'car': 909000039,
    'dust': 909000039,
    'lol': 909000002,
    'laugh': 909000002,
    'cobra': 909000072,
    'ghost': 909036001,
    'fire': 909033001,
    'sholay': 909050020,
    'blade': 909050013,
    'sword': 909050013,
    
    # Basic Emotes
    'hello': 909000001,
    'hi': 909000001,
    'dab': 909000005,
    'chicken': 909000006,
    'dance': 909000008,
    'babyshark': 909000009,
    'pushup': 909000012,
    'dragon': 909000015,
    'highfive': 909000025,
    'selfie': 909000032,
    'breakdance': 909000040,
    'kungfu': 909000041,
    
    # Popular Emotes
    'thor': 909050008,
    'rasengan': 909047015,
    'ninja': 909047018,
    'clone': 909047019,
    'fireball': 909050005,
    'hammer': 909050008,

    'hello': 909000001,
    'lol': 909000002,
    'provoke': 909000003,
    'applause': 909000004,
    'dab': 909000005,
    'chicken': 909000006,
    'armwave': 909000007,
    'g18': 909038012,
    'm10red': 909039011,
    'xm8': 909000085,
    'mp40': 909000075,
    'groza': 909041005,
    'scar': 909000068,
    'pushup': 909000012,
    'chicken': 909000006,
    'puffyride': 909051014,
    'circle': 909050009,
    'petals': 909051013,
    'bow': 909051012,
    'motorbike': 909051010,
    'shower': 909051004,
    'dream': 909051002,
    'angelic': 909051001,
    'paint': 909048015,
    'sword': 909044015,
    'flar': 909041008,
    'owl': 909049003,
    'thor': 909050008,
    'bigdill': 909049001,
    'csgm': 909041013,
    'mapread': 909050014,
    'tomato': 909050015,
    'ninjasummon': 909050002,
    'lvl100': 909042007,
    '100': 909042007,
    'auraboat': 909050028,
    'flyingguns': 909049012,
    'iheartyou': 909000045,
    'pirateflag': 909000034,
    'throne': 909000014,
    'rose': 909000010,
    'valentineheart': 909038004,
    'rampagebook': 909034001,
    'guildflag': 909049017,
    'fish': 909040004,
    'inosuke': 909041003,
    'shootdance': 909000008,
    'babyshark': 909000009,
    'flowrs': 909000010,
    'mummydance': 909000011,
    'pushup': 909000012,
    'shuffling': 909000013,
    'throne': 909000014,
    'dragonfist': 909000015,
    'dangerousgame': 909000016,
    'jaguardance': 909000017,
    'threaten': 909000018,
    'shakewithme': 909000019,
    'devilsmove': 909000020,
    'furiousslam': 909000021,
    'moonflip': 909000022,
    'wigglewalk': 909000023,
    'battledance': 909000024,
    'highfive': 909000025,
    'shakeitup': 909000026,
    'gloriousspin': 909000027,
    'cranekick': 909000028,
    'partydance': 909000029,
    'jigdance': 909000031,
    'selfie': 909000032,
    'soulshaking': 909000033,
    'pirateflag': 909000034,
    'healingdance': 909000035,
    'topdj': 909000036,
    'deathglare': 909000037,
    'powerofmoney': 909000038,
    'eatmydust': 909000039,
    'breakdance': 909000040,
    'kungfu': 909000041,
    'bonappetit': 909000042,
    'aimfire': 909000043,
    'swan': 909000044,
    'iheartyou': 909000045,
    'teatime': 909000046,
    'bringiton': 909000047,
    'whyohwhy': 909000048,
    'fancyhands': 909000049,
    'shimmy': 909000051,
    'doggie': 909000052,
    'challengeon': 909000053,
    'lasso': 909000054,
    'imrich': 909000055,
    'morepractice': 909000079,
    'ffws2021': 909000080,
    'dracossoul': 909000081,
    'goodgame': 909000082,
    'greetings': 909000083,
    'walker': 909000084,
    'bornoflight': 909000085,
    'mythosfour': 909000086,
    'championgrab': 909000087,
    'winandchill': 909000088,
    'hadouken': 909000089,
    'bloodwraith': 909000090,
    'bigsmash': 909000091,
    'fancysteps': 909000092,
    'allincontrol': 909000093,
    'debugging': 909000094,
    'waggorwave': 909000095,
    'crazyguitar': 909000096,
    'poof': 909000097,
    'chosenvictor': 909000098,
    'challenger': 909000099,
    'partygame5': 909000100,
    'partygame6': 909000101,
    'partygame3': 909000102,
    'partygame4': 909000103,
    'partygame7': 909000104,
    'partygame1': 909000105,
    'partygame8': 909000106,
    'partygame2': 909000107,
    'dribbleking': 909000121,
    'ffwsguitar': 909000122,
    'mindit': 909000123,
    'goldencombo': 909000124,
    'sickmoves': 909000125,
    'rapswag': 909000126,
    'battleinstyle': 909000127,
    'rulersflag': 909000128,
    'moneythrow': 909000129,
    'endlessbullets': 909000130,
    'smoothsway': 909000131,
    'number1': 909000132,
    'fireslam': 909000133,
    'heartbroken': 909000134,
    'rockpaperscissors': 909000135,
    'shatteredreality': 909000136,
    'haloofmusic': 909000137,
    'burntbbq': 909000138,
    'switchingsteps': 909000139,
    'creedslay': 909000140,
    'leapoffail': 909000141,
    'rhythmgirl': 909000142,
    'helicoptership': 909000143,
    'kungfutigers': 909000144,
    'possessedwarrior': 909000145,
    'raiseyourthumb': 909000150,

    # 33xxx Series
    'fireborn': 909033001,
    'goldenfeather': 909033002,
    'comeanddance': 909033003,
    'dropkick': 909033004,
    'sitdown': 909033005,
    'booyahsparks': 909033006,
    'ffwsdance': 909033007,
    'easypeasy': 909033008,
    'winnerthrow': 909033009,
    'weightofvictory': 909033010,

    # 34xxx Series
    'chronicle': 909034001,
    'collapse': 909034002,
    'flaminggroove': 909034003,
    'energetic': 909034004,
    'ridicule': 909034005,
    'teasewaggor': 909034006,
    'greatconductor': 909034007,
    'fakedeath': 909034008,
    'twerk': 909034009,
    'brheroic': 909034010,
    'brmaster': 909034011,
    'csheroic': 909034012,
    'csmaster': 909034013,
    'yesido': 909034014,

    # 35xxx Series
    'freemoney': 909035001,
    'singersb03': 909035002,
    'singersb0203': 909035003,
    'singersb010203': 909035004,
    'victoriouseagle': 909035005,
    'flyingsaucer': 909035006,
    'weaponmagician': 909035007,
    'bobbledance': 909035008,
    'weighttraining': 909035009,
    'beautifullove': 909035010,
    'groovemoves': 909035011,
    'howlersrage': 909035012,
    'louderplease': 909035013,
    'ninjastand': 909035014,
    'creatorinaction': 909035015,

    # 36xxx Series
    'ghostfloat': 909036001,
    'shibasurf': 909036002,
    'waiterwalk': 909036003,
    'grafficameraman': 909036004,
    'agileboxer': 909036005,
    'sunbathing': 909036006,
    'skateboardswag': 909036008,
    'phantomtamer': 909036009,
    'signal': 909036010,
    'eternaldescent': 909036011,
    'swaggydance': 909036012,
    'admire': 909036014,

    # 37xxx Series
    'reindeerfloat': 909037001,
    'bamboodance': 909037002,
    'constellationdance': 909037003,
    'trophygrab': 909037004,
    'starryhands': 909037005,
    'yum': 909037006,
    'happydancing': 909037007,
    'juggle': 909037008,
    'neonsign': 909037009,
    'beasttease': 909037010,
    'drachentear': 909037011,
    'clapdance': 909037012,

    # 38xxx Series
    'influencer': 909038001,
    'macarena': 909038002,
    'technoblast': 909038003,
    'valentine': 909038004,
    'angrywalk': 909038005,
    'makesomenoise': 909038006,
    'crocohooray': 909038008,
    'scorpionspin': 909038009,
    'cindersummon': 909038010,
    'shallwedance': 909038011,
    'g18': 909038012,
    'spinmaster': 909038013,

    # 39xxx Series
    'festival': 909039001,
    'artisticdance': 909039002,
    'forwardbackward': 909039003,
    'scorpionfriend': 909039004,
    'achingpower': 909039005,
    'earthlyforce': 909039006,
    'grenademagic': 909039007,
    'ohyeah': 909039008,
    'graceonwheels': 909039009,
    'flex': 909039010,
    'm10red': 909039011,
    'firebeasttamer': 909039012,
    'crimsontunes': 909039013,
    'swaggyvsteps': 909039014,

    # 40xxx Series
    'chromaticfinish': 909040001,
    'smashthefeather': 909040002,
    'sonoroussteps': 909040003,
    'fish': 909040004,
    'chromaticpop': 909040005,
    'chromatwist': 909040006,
    'birthofjustice': 909040008,
    'spidersense': 909040009,
    'chromasonicshot': 909040010,
    'playwiththunderbolt': 909040011,
    'anniversary': 909040012,
    'wisdomswing': 909040013,

    # 41xxx Series
    'thunderflash': 909041001,
    'whirlpool': 909041002,
    'inosuke': 909041003,
    'flyinginksword': 909041004,
    'groza': 909041005,
    'dancepuppet': 909041006,
    'highknees': 909041007,
    'flar': 909041008,
    'feeltheelectricity': 909041009,
    'whacacotton': 909041010,
    'honorablemention': 909041011,
    'brgrandmaster': 909041012,
    'csgm': 909041013,
    'monsterclubbing': 909041014,
    'basudaradance': 909041015,

    # 42xxx Series
    'stirfryfrostfire': 909042001,
    'moneyrain': 909042002,
    'frostfirecalling': 909042003,
    'stompingfoot': 909042004,
    'thisway': 909042005,
    'excellentservice': 909042006,
    'lvl100': 909042007,
    'realtiger': 909042008,
    'celebrationschuss': 909042009,
    'dawnvoyage': 909042011,
    'lamborghiniride': 909042012,
    'toiletman': 909042013,
    'handgrooves': 909042016,
    'kemusan': 909042018,

    # 43xxx Series
    'ribbitrider': 909043001,
    'innerself': 909043002,
    'emperortreasure': 909043003,
    'whysochaos': 909043004,
    'hugefeast': 909043005,
    'colorburst': 909043006,
    'dragonswipe': 909043007,
    'samba': 909043008,
    'speedsummon': 909043009,
    'whatamatch': 909043010,
    'whatapair': 909043013,

    # 44xxx Series
    'bytemounting': 909044001,
    'unicyclist': 909044002,
    'basketrafting': 909044003,
    'happylamb': 909044004,
    'paradox': 909044005,
    'harmoniousparadox': 909044006,
    'raiseyourthumb2': 909044007,
    'claphands': 909044008,
    'donedeal': 909044009,
    'starcatcher': 909044010,
    'paradoxwings': 909044011,
    'zombified': 909044012,
    'sword': 909044015,
    'honkup': 909044016,

    # 45xxx Series
    'cyclone': 909045001,
    'springrocker': 909045002,
    'giddyup': 909045003,
    'goosydance': 909045004,
    'captainvictor': 909045005,
    'youknowimgood': 909045006,
    'stepstep': 909045007,
    'superyay': 909045008,
    'moonwalk': 909045009,
    'flowersalute': 909045010,
    'foxyrun': 909045011,
    'waggorsseesaw': 909045012,
    'floatingmeditation': 909045015,
    'naatunaatu': 909045016,
    'championswalk': 909045017,

    # 46xxx Series
    'auraboarder': 909046001,
    'booyahchamp': 909046002,
    'controlledcombustion': 909046003,
    'cheerstovictory': 909046004,
    'shoeshining': 909046005,
    'gunspinning': 909046006,
    'crowdpleaser': 909046007,
    'nosweat': 909046008,
    'magmaquake': 909046009,
    'maxfirepower': 909046010,
    'canttouchthis': 909046011,
    'firestarter': 909046012,
    'ffwsflag': 909046013,
    'beatdrop': 909046014,
    'spatialawareness': 909046015,
    'trapping': 909046016,
    'soaringup': 909046017,

    # 47xxx Series
    'wontbowdown': 909047001,
    'aurora': 909047002,
    'couchfortwo': 909047003,
    'flutterdash': 909047004,
    'slipperythrone': 909047005,
    'acceptancespeech': 909047006,
    'lovemelovemenot': 909047007,
    'scissorsavvy': 909047008,
    'thinker': 909047009,
    'matchcountdown': 909047010,
    'hiptwists': 909047011,
    'jkt48': 909047012,
    'stormyascent': 909047013,
    'rasengan': 909047015,
    'thousandyears': 909047016,
    'ninjasign': 909047017,
    'ninjarun': 909047018,
    'clonejutsu': 909047019,

    # 48xxx Series
    'rescue': 909048001,
    'midnightperuse': 909048002,
    'guitargroove': 909048003,
    'keyboardplayer': 909048004,
    'ondrums': 909048005,
    'chacchac': 909048006,
    'pillowfight': 909048007,
    'targetpractice': 909048008,
    'goofycamel': 909048009,
    'hitasix': 909048010,
    'flagsummon': 909048011,
    'swiftsteps': 909048012,
    'carnivalfunk': 909048013,
    'slurp': 909048014,
    'paint': 909048015,
    'halftime': 909048016,
    'throwin': 909048017,
    'bailalorocky': 909048018,

    # 49xxx Series
    'bigdill': 909049001,
    'handraise': 909049002,
    'owl': 909049003,
    'slapandtwist': 909049004,
    'sidewiggle': 909049005,
    'creationdays': 909049006,
    'rainingcoins': 909049007,
    'clapclaphooray': 909049008,
    'infiniteloops': 909049009,
    'p90surfer': 909049010,
    'boxingmachine': 909049011,
    'flyingguns': 909049012,
    'comicbarf': 909049013,
    'driveby': 909049014,
    'pedalmetal': 909049015,
    'spearspin': 909049016,
    'guildflag': 909049017,
    'discodazzle': 909049018,
    'squatchallenge': 909049019,
    'winninggoal': 909049020,
    'headhigh': 909049021,

    # 50xxx Series
    'ninjasummon': 909050002,
    'finalbattle': 909050003,
    'foreheadpoke': 909050004,
    'fireballjutsu': 909050005,
    'flyingraijin': 909050006,
    'thor': 909050008,
    'circle': 909050009,
    'drumtwirl': 909050010,
    'bunnyaction': 909050011,
    'broomswoosh': 909050012,
    'bladefromheart': 909050013,
    'mapread': 909050014,
    'tomato': 909050015,
    'tacticalmoveout': 909050016,
    'bunnywiggle': 909050017,
    'flamingheart': 909050018,
    'rainorshine': 909050019,
    'sholay': 909050020,
    'peakpoints': 909050021,

    # 51xxx Series
    'dream': 909051002,
    'angelic': 909051001,
    'shower': 909051004,
    'motorbike': 909051010,
    'bow': 909051012,
    'petals': 909051013,
    'puffyride': 909051014,
}    

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
   
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
        

# --- START: ADD THIS NEW AND IMPROVED FUNCTION ---
def send_vistttt(uid):
    try:
        # Step 1: Validate the UID first to avoid unnecessary API calls.
        info_response = newinfo(uid)
        if info_response.get('status') != "ok":
            return (
                f"[b][c][FF0000]╔═══════「 ❌ Error ❌ 」═══════╗\n\n"
                f"[FFFFFF]Invalid Player ID: [FFFF00]{fix_num(uid)}\n"
                f"[FFFFFF]Please check the number and try again.\n\n"
                f"[FF0000]╚═══════════════════════════╝"
            )

        # Step 2: Call the new visit API.
        api_url = f"https://visit-api-316h.vercel.app/ind/{uid}"
        response = requests.get(api_url, timeout=15)

        # Step 3: Process the API response.
        if response.status_code == 200:
            data = response.json()
            success_count = data.get('success', 0)

            if success_count > 0:
                # Extract all details from the successful response.
                nickname = data.get('nickname', 'N/A')
                level = data.get('level', 'N/A')
                likes = data.get('likes', 0)
                region = data.get('region', 'N/A')
                
                # Format a premium success message.
                return (
                    f"[b][c][FF0000]╔═ ✅ Visit Success ✅ ═╗\n\n"
                    f"[FFFFFF]Successfully sent [FFFF00]{success_count}[FFFFFF] visits to:\n\n"
                    f"[00BFFF]👤 Nickname: [FFFFFF]{nickname}\n"
                    f"[00BFFF]🆔 Player ID: [FFFFFF]{fix_num(uid)}\n"
                    f"[00BFFF]🎖️ Level: [FFFFFF]{level}\n"
                    f"[00BFFF]❤️ Likes: [FFFFFF]{fix_num(likes)}\n"
                    f"[00BFFF]🌏 Region: [FFFFFF]{region}\n\n"
                    f"[FF0000]╚══════════╝"
                )
            else:
                # Handle cases where the API returns a success status but sends 0 visits.
                return (
                    f"[b][c][FF0000]╔═════「 ⚠️ Warning ⚠️ 」═════╗\n\n"
                    f"[FFFFFF]API call was successful, but no visits\n"
                    f"[FFFFFF]were sent. This might be a daily limit.\n\n"
                    f"[FF0000]╚══════════════════════════╝"
                )
        else:
            # Handle API server errors.
            return (
                f"[b][c][FF0000]╔═══════「 ❌ API Error ❌ 」═══════╗\n\n"
                f"[FFFFFF]The visit server returned an error.\n"
                f"[FFFFFF]Status Code: [FFFF00]{response.status_code}\n\n"
                f"[FF0000]╚════════════════════════════╝"
            )

    except requests.exceptions.RequestException as e:
        # Handle network or connection errors.
        return (
            f"[b][c][FF0000]╔════「 🔌 Connection Error 🔌 」════╗\n\n"
            f"[FFFFFF]Could not connect to the visit API server.\n"
            f"[FFFFFF]Please try again later.\n\n"
            f"[FF0000]╚══════════════════════════════╝"
        )
    except Exception as e:
        # Handle any other unexpected errors.
        logging.error(f"An unexpected error occurred in send_vistttt: {str(e)}")
        return (
            f"[b][c][FF0000]╔════「 ⚙️ System Error ⚙️ 」════╗\n\n"
            f"[FFFFFF]An unexpected error occurred.\n"
            f"[FFFFFF]Check the logs for more details.\n\n"
            f"[FF0000]╚══════════════════════════╝"
        )
# --- END: ADD THIS NEW AND IMPROVED FUNCTION ---

    except requests.exceptions.RequestException as e:
        # Handle network connection errors.
        return (
            f"[FF0000]________________________\n"
            f"Failed to connect to the server:\n"
            f"{str(e)}\n"
            f"________________________\n"
        )
    except Exception as e:
        # Handle other potential errors, like JSON parsing issues.
        return (
            f"[FF0000]________________________\n"
            f"An unexpected error occurred: {str(e)}\n"
            f"________________________\n"
        )
# --- END: ADD THIS NEW FUNCTION ---


def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
def newinfo(uid):
    try:
        # The new API URL
        url = f"https://jnl-tcp-info.vercel.app/player-info?uid={uid}"
        # Make the request with a timeout to prevent it from hanging
        response = requests.get(url, timeout=15)

        # A successful request returns status code 200
        if response.status_code == 200:
            data = response.json()
            # Check for a key like 'AccountName' to confirm the API returned valid data
            if "AccountName" in data and data["AccountName"]:
                return {"status": "ok", "info": data}
            else:
                # This handles cases where the API returns 200 but the ID was invalid
                return {"status": "wrong_id"}
        else:
            logging.error(f"Error: API returned status code {response.status_code} for UID {uid}")
            return {"status": "wrong_id"}

    except requests.exceptions.RequestException as e:
        # Handle network issues like timeouts or connection errors
        logging.error(f"Error during newinfo request: {str(e)}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        # Handle any other unexpected errors
        logging.error(f"An unexpected error occurred in newinfo: {str(e)}")
        return {"status": "error", "message": str(e)}
	
import requests

def send_spam(uid):
    try:
        # First, check the validity of the ID using the newinfo function
        info_response = newinfo(uid)
        
        if info_response.get('status') != "ok":
            return (
                f"[FF0000]-----------------------------------\n"
                f"Error in ID: {fix_num(uid)}\n"
                f"Please check the number\n"
                f"-----------------------------------\n"
            )
        
        # Second, send the request to the correct link using the ID
        api_url = f"https://spam-free.vercel.app/spam?id={uid}"
        response = requests.get(api_url)
        
        # Third, check if the request was successful
        if response.status_code == 200:
            return (
                f"{generate_random_color()}-----------------------------------\n"
                f"Friend request sent successfully ✅\n"
                f"To: {fix_num(uid)}\n"
                f"-----------------------------------\n"
            )
        else:
            return (
                f"[FF0000]-----------------------------------\n"
                f"Failed to send (Error code: {response.status_code})\n"
                f"-----------------------------------\n"
            )
            
    except requests.exceptions.RequestException as e:
        # Handle network connection errors
        return (
            f"[FF0000]-----------------------------------\n"
            f"Failed to connect to the server:\n"
            f"{str(e)}\n"
            f"-----------------------------------\n"
        )
def attack_profail(player_id):
    url = f"https://visit-taupe.vercel.app/visit/{player_id}"
    res = requests.get(url)
    if res.status_code() == 200:
        logging.info("Done-Attack")
    else:
        logging.error("Fuck-Attack")

def send_likes(uid):
    try:
        # Attempt to connect to the new likes API for the IND server
        likes_api_response = requests.get(
            f"https://private-like-api.vercel.app/like?uid={uid}&server_name=ind&key=Nilay-Ron",
            timeout=15  # Add a timeout to prevent it from hanging
        )
        
        # Check if the API request was successful
        if likes_api_response.status_code == 200:
            api_json_response = likes_api_response.json()
            
            # Extract the nested "response" object
            response_data = api_json_response.get('response', {})
            
            # Extract relevant fields
            likes_added = response_data.get('LikesGivenByAPI', 0)
            player_name = response_data.get('PlayerNickname', 'Unknown')
            likes_before = response_data.get('LikesbeforeCommand', 0)
            likes_after = response_data.get('LikesafterCommand', 0)
            key_remaining = response_data.get('KeyRemainingRequests', 'N/A')
            
            if likes_added == 0:
                # Case: Daily limit reached or no likes added
                return {
                    "status": "failed",
                    "message": (
                        f"[C][B][FF0000]________________________\n"
                        f" ❌ Daily limit for sending likes reached!\n"
                        f" Try again after 24 hours\n"
                        f" ❤️ Key Remaining: [00FFFF]{key_remaining}\n"
                        f"________________________"
                    )
                }
            else:
                # Case: Success with details
                return {
                    "status": "ok",
                    "message": (
                        f"[C][B][00FF00]________________________\n"
                        f" ✅ Added {likes_added} likes\n"
                        f" Name: {player_name}\n"
                        f" Previous Likes: {likes_before}\n"
                        f" New Likes: {likes_after}\n"
                        f" ❤️ Key Remaining: [00FFFF]{key_remaining}\n"
                        f"________________________"
                    )
                }
        else:
            # Case: General API failure
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ Sending error!\n"
                    f" Please check the validity of the User ID\n"
                    f"________________________"
                )
            }

    except requests.exceptions.RequestException:
        # Handle network errors (e.g., API is not running)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ API Connection Failed!\n"
                f" Please ensure the API server is running\n"
                f"________________________"
            )
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ An unexpected error occurred: {str(e)}\n"
                f"________________________"
            )
        }

def get_info(uid):
    try:
        # Attempt to connect to the player info API
        info_api_response = requests.get(
            f"https://jnl-tcp-info.vercel.app/player-info?uid={uid}",
            timeout=15  # Add a timeout to prevent it from hanging
        )
        
        # Check if the API request was successful
        if info_api_response.status_code == 200:
            api_json_response = info_api_response.json()
            
            # Extract relevant fields from the response
            account_name = api_json_response.get('AccountName', 'Unknown')
            account_level = api_json_response.get('AccountLevel', 0)
            account_likes = api_json_response.get('AccountLikes', 0)
            account_region = api_json_response.get('AccountRegion', 'Unknown')
            br_max_rank = api_json_response.get('BrMaxRank', 0)
            cs_max_rank = api_json_response.get('CsMaxRank', 0)
            guild_name = api_json_response.get('GuildName', 'None')
            signature = api_json_response.get('signature', 'No signature')

            # Case: Success with player details
            return {
                "status": "ok",
                "message": (
                    f"[C][B][00FF00]________________________\n"
                    f" ✅ Player Information\n"
                    f" Name: {account_name}\n"
                    f" Level: {account_level}\n"
                    f" Likes: {account_likes}\n"
                    f" Region: {account_region}\n"
                    f" BR Max Rank: {br_max_rank}\n"
                    f" CS Max Rank: {cs_max_rank}\n"
                    f" Guild: {guild_name}\n"
                    f" Signature: {signature}\n"
                    f"________________________"
                )
            }
        else:
            # Case: General API failure
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ Failed to fetch player info!\n"
                    f" Please check the validity of the User ID\n"
                    f"________________________"
                )
            }

    except requests.exceptions.RequestException:
        # Handle network errors (e.g., API is not running)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ API Connection Failed!\n"
                f" Please ensure the API server is running\n"
                f"________________________"
            )
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ An unexpected error occurred: {str(e)}\n"
                f"________________________"
            )
        }        
		
def Encrypt(number):
    number = int(number)  # Convert the number to an integer
    encoded_bytes = []    # Create a list to store the encoded bytes

    while True:  # Loop that continues until the number is fully encoded
        byte = number & 0x7F  # Extract the least 7 bits of the number
        number >>= 7  # Shift the number to the right by 7 bits
        if number:
            byte |= 0x80  # Set the eighth bit to 1 if the number still contains additional bits

        encoded_bytes.append(byte)
        if not number:
            break  # Stop if no additional bits are left in the number

    return bytes(encoded_bytes).hex()
    


def get_random_avatar():
	avatar_list = [
         '902048021'
    ]
	random_avatar = random.choice(avatar_list)
	return  random_avatar

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                logging.error("Connection closed by remote host")
                break
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        logging.error(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# --- START: Modified for improved error handling ---
# This function is now the single point for safely restarting the script.
def restart_program():
    logging.warning("Initiating bot restart...")
    try:
        p = psutil.Process(os.getpid())
        # Close open file descriptors
        for handler in p.open_files() + p.net_connections():
            try:
                os.close(handler.fd)
            except Exception as e:
                logging.error(f"Failed to close handler {handler.fd}: {e}")
    except Exception as e:
        logging.error(f"Error during pre-restart cleanup: {e}")
    
    # Replace the current process with a new instance of the script
    python = sys.executable
    os.execl(python, python, *sys.argv)
# --- END: Modified for improved error handling ---
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        # --- START: Added for periodic restart ---
        # Record the start time to track uptime.
        self.start_time = time.time()
        # --- END: Added for periodic restart ---
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            logging.info(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            logging.error(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            logging.error(f"Error in nmnmmmmn: {e}")

    
    def send_emote(self, target_id, emote_id):
        """
        Creates and prepares the packet for sending an emote to a target player.
        """
        fields = {
            1: 21,
            2: {
                1: 804266360,  # Constant value from original code
                2: 909000001,  # Constant value from original code
                5: {
                    1: int(target_id),
                    3: int(emote_id),
                }
            }
        }
        packet = create_protobuf_packet(fields).hex()
        # The packet type '0515' is used for online/squad actions
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        else:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)    
        
        
    def send_emotee(self, targ_id, emote_id):
        """
        Creates and prepares the packet for sending an emote to a target player.
        """
        fields = {
            1: 21,
            2: {
                1: 804266360,  # Constant value from original code
                2: 909000001,  # Constant value from original code
                5: {
                    1: int(targ_id),
                    3: int(join_emote_id),
                }
            }
        }
        packet = create_protobuf_packet(fields).hex()
        # The packet type '0515' is used for online/squad actions
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        else:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)            
    
    
    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "iG:[C][B][FF0000] BOSS",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "IND",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 12480598706
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "IND",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)    
    def request_join_squad(self, idplayer):
        same_value = random.choice([4096])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)   
    def request_join_squadd(self, idplayer):
        same_value = random.choice([16384])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)               
    def Maqbara1(self, client_id):
        key, iv = self.key, self.iv
        fields = {
        1: int(client_id),
      2: 5,
      4: 50,
      5: {
        1: int(client_id),
        2: "[00ff00]Jadui",
            3: 1
          }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)            
    def request_join_squaddd(self, idplayer):
        same_value = random.choice([8192])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)            
    def request_join_squadddd(self, idplayer):
        same_value = random.choice([1048576])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)         
    def request_join_squaddddd(self, idplayer):
        same_value = random.choice([32768])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)                                   
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_join_squadddddd(self, idplayer):
        same_value = random.choice([64])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] KRISHNA",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)                     
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 12480598706,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 12480598706
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 12480598706
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        #logging.info(Besto_Packet)
    def boss(self, client_id):
        key, iv = self.key, self.iv
        banner_text = f"""
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███
[b][FF0000]███[FFFFFF]███[000000]███[00FF00]███[0000FF]███[FFFF00]███[FFA500]███[FFC0CB]███[FF00FF]███[800080]███[808080]███[C0C0C0]███[A52A2A]███[FFD700]███[00FFFF]███[008080]███[00008B]███[ADD8E6]███[008000]███[800000]███[FF0000]███[FFFFFF]███[000000]███


         """        
        fields = {
            1: 5,
            2: {
                1: int(client_id),
                2: 1,
                3: int(client_id),
                4: banner_text
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)    

    def boss1(self, client_id):
        key, iv = self.key, self.iv
        gay_text = f"""
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.
.



[0000FF]███████╗██╗   ██╗ ██████╗██╗  ██╗
██╔════╝██║   ██║██╔════╝██║ ██╔╝
[87CEEB]█████╗  ██║   ██║██║     █████╔╝ 
[00FF00]██╔══╝  ██║   ██║██║     ██╔═██╗ 
██║     ╚██████╔╝╚██████╗██║  ██╗
[82C8E5]██████████████████████████████

[B][C][00FF00] BOSS
[ff0000]━━━━━━━━━━━━━━━━━━━━━
[B][C][FF9900]D O N EㅤH A C K I N G
[B][C][E75480]Y O U RㅤA C C O U N T
[81DACA]━━━━━━━━━━━━━━━━━━━━━
[B][C][FF0000]F U C KㅤY O U
[CCFFCC]━━━━━━━━━━━━━━━━━━━━━
[B][C][81DACA]P O W E R E DㅤB Y BOSS 
[FFFF00]━━━━━━━━━━━━━━━━━━━━━
[B][C][00FF00]F O L L O WㅤM EㅤI NㅤI N S T A G R A Mㅤ[FFFFFF]@
[00008B]━━━━━━━━━━━━━━━━━━━━━
[B][C][81DACA]I FㅤY O UㅤN O TㅤF A L L O WㅤM EㅤIㅤW I L LㅤB A NㅤY O U RㅤA C C O U N T


         """        
        fields = {
            1: int(client_id),
            2: 5,
            4: 50,
            5: {
                1: int(client_id),
                2: gay_text,
                3: 1
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, self.key, self.iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        
    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
                1: 12947146032,
                2: Enc_Id,
                3: 2,
                4: str(Msg),
                5: int(datetime.now().timestamp()),
                7: 2,
                9: {
                    1: " PROTO", #RON PROTO DONT CHANGE 
                    2: int(get_random_avatar()),
                    3: 901048020,
                    4: 330,
                    5: 1001000003,
                    8: "Friend",
                    10: 1,
                    11: 1,
                    13: {
                        1: 2,
                        2: 1,
                    },
                    14: {
                        1: 11017917409,
                        2: 8,
                        3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
                    }
                },
                10: "IND",
                13: {
                    1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",
                    2: 1,
                    3: 1
                },
                14: {
                    1: {
                        1: random.choice([1, 4]),
                        2: 1,
                        3: random.randint(1, 180),
                        4: 1,
                        5: int(datetime.now().timestamp()),
                        6: "IND"
                    }
                }
            }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "BOSS",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip,online_port))
        logging.info(f" Con port {online_port} Host {online_ip} ")
        #logging.info(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            try:
                # --- START: Added for periodic restart ---
                if time.time() - self.start_time > 600: # 10 minutes * 60 seconds
                    logging.warning("Scheduled 10-minute restart from sockf1.")
                    restart_program()
                # --- END: Added for periodic restart ---

                data2 = socket_client.recv(9999)
                #logging.info(data2)
                if "0500" in data2.hex()[0:4]:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    fark = parsed_data.get("4", {}).get("data", None)
                    if fark is not None:
                        #logging.info(f"haaaaaaaaaaaaaaaaaaaaaaho {fark}")
                        if fark == 18:
                            if sent_inv:
                                accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                                #logging.info(accept_packet)
                                #logging.info(tempid)
                                aa = gethashteam(accept_packet)
                                ownerid = getownteam(accept_packet)
                                #logging.info(ownerid)
                                #logging.info(aa)
                                ss = self.accept_sq(aa, tempid, int(ownerid))
                                socket_client.send(ss)
                                sleep(1)
                                startauto = self.start_autooo()
                                socket_client.send(startauto)
                                start_par = False
                                sent_inv = False
                        if fark == 6:
                            leaveee = True
                            logging.info("kaynaaaaaaaaaaaaaaaa")
                        if fark == 50:
                            pleaseaccept = True
                    #logging.info(data2.hex())

                if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                        accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                        kk = get_available_room(accept_packet)
                        parsed_data = json.loads(kk)
                        #logging.info(parsed_data)
                        idinv = parsed_data["5"]["data"]["1"]["data"]
                        nameinv = parsed_data["5"]["data"]["3"]["data"]
                        senthi = True
                if "0f00" in data2.hex()[0:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    #logging.info(packett)
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    
                    asdj = parsed_data["2"]["data"]
                    tempdata = get_player_status(packett)
                    if asdj == 15:
                        if tempdata == "OFFLINE":
                            tempdata = f"The id is {tempdata}"
                        else:
                            idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                            idplayer1 = fix_num(idplayer)
                            if tempdata == "IN ROOM":
                                idrooom = get_idroom_by_idplayer(packett)
                                idrooom1 = fix_num(idrooom)
                                
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}"
                                data22 = packett
                                #logging.info(data22)
                                
                            if "INSQUAD" in tempdata:
                                idleader = get_leader(packett)
                                idleader1 = fix_num(idleader)
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}"
                            else:
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}"
                        statusinfo = True 

                        #logging.info(data2.hex())
                        #logging.info(tempdata)
                    
                        

                    else:
                        pass
                if "0e00" in data2.hex()[0:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    #logging.info(packett)
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    idplayer1 = fix_num(idplayer)
                    asdj = parsed_data["2"]["data"]
                    tempdata1 = get_player_status(packett)
                    if asdj == 14:
                        nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                        
                        maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                        maxplayer1 = fix_num(maxplayer)
                        nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                        nowplayer1 = fix_num(nowplayer)
                        tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                        #logging.info(tempdata1)
                        

                        
                    
                        
                if data2 == b"":
                    
                    logging.error("Connection closed by remote host in sockf1. Restarting.")
                    restart_program()
                    break
            except Exception as e:
                logging.critical(f"Unhandled error in sockf1 loop: {e}. Restarting bot.")
                restart_program()
    
    
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            # --- START: Added for periodic restart and error handling ---
            if time.time() - self.start_time > 600: # 10 minutes * 60 seconds
                logging.warning("Scheduled 10-minute restart from connect loop.")
                restart_program()
            
            try:
            # --- END: Added for periodic restart and error handling ---
                data = clients.recv(9999)

                if data == b"":
                    logging.error("Connection closed by remote host in connect loop. Restarting.")
                    restart_program()
                    break
                #logging.info(f"Received data: {data}")
                
                if senthi == True:
                    
                    clients.send(
                            self.GenResponsMsg(
                                f"""[C][B][FF1493]╔══════════════════════════╗
[FFFFFF]✨ Hello!  
[FFFFFF]❤️ Thank you for adding me!  
[FFFFFF]⚡ To see my commands:  
[FFFFFF]👉 Send /help or any emoji  
[FF1493]╠══════════════════════════╣
[FFFFFF]🤖 Want to buy a bot?  
[FFFFFF]📩 Contact the developer  
[FFD700]👑 NAME : [FFFF00]BOSS  ⚡   
[FFD700]📌 Instagram : [00BFFF]@lsmonster1 
[FF1493]╚══════════════════════════╝""", idinv
                            )
                    )
                    senthi = False
                
                
                
                if "1200" in data.hex()[0:4]:
                
                    json_result = get_available_room(data.hex()[10:])
                    #logging.info(data.hex())
                    parsed_data = json.loads(json_result)
                    try:
                        uid = parsed_data["5"]["data"]["1"]["data"]
                    except KeyError:
                        logging.warning("Warning: '1' key is missing in parsed_data, skipping...")
                        uid = None  # Set a default value
                    if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                        uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                        if uexmojiii == "DefaultMessageWithKey":
                            pass
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                f"""[FFD700][c]━━━━━━━━━━━━━━━━━━━━[/c]

[FFD700][b][c]✨ WELCOME BROTHER ✨[/c][/b]
[FFFFFF][c]I'm here to assist you anytime![/c]

[FFFFFF][b][c]Use:[00FFAA] /🤔help [FFFFFF] for all commands[/c][/b]

[FFD700][c]━━━━━━━━━━━━━━━━━━━━[/c]

[FFFFFF][b][c]Follow Instagram:[/c][/b]
[00BFFF][c]@lsmonster1[/c]

[FFFFFF][b][c]Developer:[FFD700] LS BOSS[/c][/b]

[FFD700][c]━━━━━━━━━━━━━━━━━━━━[/c]""",uid
                                )
                            )
                    else:
                        pass  


                    
                


                if "1200" in data.hex()[0:4] and b"/admin" in data:
                    try:
                        i = re.split("/admin", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(
                            self.GenResponsMsg(
                                f"""[C][B][FFFFFF]╔═════[00BFFF]═════╗
[FFFFFF]✨ follow on Instagram   
[FFFFFF]          ⚡[FFFF00] BOSS ❤️  
[FFFFFF]                   thank for support 
[00BFFF]╠═════[FFFFFF]═════╣
[FFFFFF]⚡ OWNER : [FFFF00] LS BOSS   
[FFFFFF]⚡ TELEGRAM : [FFFF00]@BOSS_CODEX1 
[FFFFFF]✨ Name on instagram : [FFFF00]_ @lsmonster1❤️  
[00BFFF]╚═════[FFFFFF]═════╝
[FFFFFF]✨ Developer —͟͞͞ </> [FFFF00] BOSS_CODEX  ⚡""", uid
                            )
                        )
                    except Exception as e:
                        logging.error(f"Error processing /admin command: {e}. Restarting.")
                        restart_program()
                

                if "1200" in data.hex()[0:4] and b"/s1" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s1\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s1 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squad(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s1 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s1 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()
                        
                        
                if "1200" in data.hex()[0:4] and b"/s2" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s2\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s2 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squaddddd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s2 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s2 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()                        
                        
                        

                if "1200" in data.hex()[0:4] and b"/s3" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s3\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s3 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squaddddd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s3 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s3 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()                        
                        
                        
                if "1200" in data.hex()[0:4] and b"/s4" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s4\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s4 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squadddddd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s4 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s4 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()                                                
                        
                        
                if "1200" in data.hex()[0:4] and b"/s5" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s5\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s5 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squadddd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s5 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s5 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()
                                                
                        
                        
                if "1200" in data.hex()[0:4] and b"/s6" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s6\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /s6 spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squaddd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s6 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s6 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()                        
                        
                        
                if "1200" in data.hex()[0:4] and b"/s7" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/s7\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /sm spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squadd(player_id_str)
                            spam_count = 5  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /s7 <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /s7 command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()                        
                        
                        
                if "1200" in data.hex()[0:4] and b"/x" in data:
                    try:
                        command_split = re.split("/x ", str(data))
                        if len(command_split) > 1:
                            player_id = command_split[1].split('(')[0].strip()
                            if "***" in player_id:
                                player_id = player_id.replace("***", "106")

                            json_result = get_available_room(data.hex()[10:])
                            if not json_result:
                                logging.error("Error: Could not parse incoming packet for /x command.")
                                continue 
                            parsed_data = json.loads(json_result)
                            
                            uid = parsed_data["5"]["data"]["1"]["data"]

                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]6 Player Squad Spam Started for {player_id} ...!!!\n",
                                    uid
                                )
                            )

                            def squad_invite_cycle():
                                try:
                                    # Create squad
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(0.2)

                                    # Change to 6-player squad
                                    packetfinal = self.changes(5)
                                    socket_client.send(packetfinal)

                                    # Send invite to target player
                                    invitess = self.invite_skwad(player_id)
                                    socket_client.send(invitess)

                                    # Leave squad and go back to solo to repeat the cycle
                                    sleep(0.5)
                                    leavee = self.leave_s()
                                    socket_client.send(leavee)
                                    sleep(0.6)
                                    change_to_solo = self.changes(1)
                                    socket_client.send(change_to_solo)
                                except Exception as e:
                                    logging.error(f"Error inside squad_invite_cycle: {e}")

                            invite_threads = []
                            for _ in range(29): 
                                t = threading.Thread(target=squad_invite_cycle)
                                t.start()
                                invite_threads.append(t)
                                time.sleep(1.0) 

                            for t in invite_threads:
                                t.join() 
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Spam finished for {player_id}!",
                                    uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"An unexpected error occurred in the /x command: {e}. Restarting.")
                        restart_program()
                    

                       

                if "1200" in data.hex()[0:4] and b"/3" in data:
                    try:
                        i = re.split("/3", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)

                        packetfinal = self.changes(2)
                        socket_client.send(packetfinal)
                        sleep(0.5)

                        room_data = None
                        if b'(' in data:
                            split_data = data.split(b'/3')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                else:
                                    iddd = uid
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              3 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> BOSS   ⚡""",
                                    uid
                                )
                            )

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /3 command: {e}. Restarting.")
                        restart_program()
                        
                
                if "1200" in data.hex()[0:4] and b"/4" in data:
                    try:
                        i = re.split("/4", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)

                        packetfinal = self.changes(3)
                        socket_client.send(packetfinal)

                        room_data = None
                        uid = parsed_data["5"]["data"]["1"]["data"] # Define uid here
                        iddd = uid # Default to sender's id
                        if b'(' in data:
                            split_data = data.split(b'/4')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              4 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> _ 
BOSS   ⚡""",
                                    uid))

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(2)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /4 command: {e}. Restarting.")
                        restart_program()                
                
                
                if "1200" in data.hex()[0:4] and b"/5" in data:
                    try:
                        i = re.split("/5", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)

                        packetfinal = self.changes(4)
                        socket_client.send(packetfinal)

                        room_data = None
                        uid = parsed_data["5"]["data"]["1"]["data"] # Define uid here
                        iddd = uid # Default to sender's id
                        if b'(' in data:
                            split_data = data.split(b'/5')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              5 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </>  BOSS  ⚡""",
                                    uid))

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(2)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /5 command: {e}. Restarting.")
                        restart_program()
                 

                
                    
                if "1200" in data.hex()[0:4] and b"/6" in data:
                    try:
                        i = re.split("/6", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)
                        packetfinal = self.changes(5)
                        
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        iddd = uid
                        if b'(' in data:
                            split_data = data.split(b'/6')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        socket_client.send(packetfinal)
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                        f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              6 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </>  BOSS  ⚡""",
                                    uid))

                        sleep(4)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(0.5)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /6 command: {e}. Restarting.")
                        restart_program()


                if "1200" in data.hex()[0:4] and b"/status" in data:
                    try:
                        i = re.split("/status", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/status', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            player_id = room_data[0]
                            packetmaker = self.createpacketinfo(player_id)
                            socket_client.send(packetmaker)
                            statusinfo1 = True
                            while statusinfo1:
                                if statusinfo == True:
                                    if "IN ROOM" in tempdata:
                                        inforoooom = self.info_room(data22)
                                        socket_client.send(inforoooom)
                                        sleep(0.5)
                                        clients.send(self.GenResponsMsg(f"{tempdata1}", uid))  
                                        tempdata = None
                                        tempdata1 = None
                                        statusinfo = False
                                        statusinfo1 = False
                                    else:
                                        clients.send(self.GenResponsMsg(f"{tempdata}", uid))  
                                        tempdata = None
                                        tempdata1 = None
                                        statusinfo = False
                                        statusinfo1 = False
                        else:
                            clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter a player ID!", uid))  
                    except Exception as e:
                        logging.error(f"Error in /status command: {e}. Restarting.")
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            uid = json.loads(get_available_room(data.hex()[10:]))["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]ERROR! Bot will restart.", uid))
                        except:
                            pass
                        restart_program()
                
             
                if "1200" in data.hex()[0:4] and b"/inv" in data:
                    try:
                        i = re.split("/inv", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/inv', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                            numsc1 = "5"

                            if numsc1 is None:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/inv 123[c]456[c]78 4\n/inv 123[c]456[c]78 5", uid
                                    )
                                )
                            else:
                                numsc = int(numsc1) - 1
                                if int(numsc1) < 3 or int(numsc1) > 6:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][FF0000] Usage : /inv <uid> <Squad Type>\n[ffffff]Example : \n/inv 12345678 4\n/inv 12345678 5", uid
                                        )
                                    )
                                else:
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(1)
                                    packetfinal = self.changes(int(numsc))
                                    socket_client.send(packetfinal)
                                    
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                                    invitessa = self.invite_skwad(iddd1)
                                    socket_client.send(invitessa)
                                    clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]Team creation is in progress and the invite has been sent! ", uid
                                )
                            )

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(5)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                        sleep(0.1)
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Bot is now in solo mode.", uid
                            )
                        )
                    except Exception as e:
                        logging.error(f"Error processing /inv command: {e}. Restarting.")
                        restart_program()
                        
                if "1200" in data.hex()[0:4] and b"/room" in data:
                    try:
                        i = re.split("/room", str(data))[1] 
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/room', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            
                            player_id = room_data[0]
                            if player_id.isdigit():
                                if "***" in player_id:
                                    player_id = rrrrrrrrrrrrrr(player_id)
                                packetmaker = self.createpacketinfo(player_id)
                                socket_client.send(packetmaker)
                                sleep(0.5)
                                if "IN ROOM" in tempdata:
                                    room_id = get_idroom_by_idplayer(data22)
                                    packetspam = self.spam_room(room_id, player_id)
                                    #logging.info(packetspam.hex())
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][00ff00]Working on your request for {fix_num(player_id)} ! ", uid
                                        )
                                    )
                                    
                                    
                                    for _ in range(99):

                                        #logging.info(" sending spam to "+player_id)
                                        threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                                    
                                    
                                    
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [00FF00]Request successful! ✅", uid
                                        )
                                    )
                                else:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]The player is not in a room", uid
                                        )
                                    )      
                            else:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write the player's ID!", uid
                                    )
                                )   

                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [FF00FF]Please write the player's ID !", uid
                                )
                            )   
                    except Exception as e:
                        logging.error(f"Error processing /room command: {e}. Restarting.")
                        restart_program()
                

                
                

                if "1200" in data.hex()[0:4] and b"WELCOME TO [FFFFF00]BOSS [ffffff]BOT" in data:
                    pass
                else:
                
                    if "1200" in data.hex()[0:4] and b"/spam" in data:
                        try:
                            command_split = re.split("/spam", str(data))
                            if len(command_split) > 1:
                                player_id = command_split[1].split('(')[0].strip()
                                #logging.info(f"Sending Spam To {player_id}")
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}Sending friend requests...", uid
                                )
                            )
                                
                                message = send_spam(player_id)
                                #logging.info(message)
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                
                                clients.send(self.GenResponsMsg(message, uid))
                        except Exception as e:
                            logging.error(f"Error processing /spam command: {e}. Restarting.")
                            restart_program()
                    if "1200" in data.hex()[0:4] and b"/visit" in data:
                        try:
                            command_split = re.split("/visit", str(data))
                            if len(command_split) > 1:
                                player_id = command_split[1].split('(')[0].strip()

                                #logging.info(f"[C][B]Sending visit To {player_id}")
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                    self.GenResponsMsg(
                        f"{generate_random_color()}Sending 1000 visits to {fix_num(player_id)}...", uid
                                    )
                                )
                                
                                message = send_vistttt(player_id)
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                
                                clients.send(self.GenResponsMsg(message, uid))
                        except Exception as e:
                            logging.error(f"Error processing /visit command: {e}. Restarting.")
                            restart_program()	                           
    #####***""?"?"?"	                    
                    if "1200" in data.hex()[0:4] and b"/info" in data:
                        try:
                            # Extract the sender's ID to send the reply back
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            sender_id = parsed_data["5"]["data"]["1"]["data"]

                            # Extract the target ID from the user's message
                            command_split = re.split("/info", str(data))
                            if len(command_split) <= 1 or not command_split[1].strip():
                                clients.send(self.GenResponsMsg("[C][B][FF0000] Please provide a player ID after the command.", sender_id))
                                continue

                            # Find the first valid-looking number string in the command text
                            uids = re.findall(r"\b\d{5,15}\b", command_split[1])
                            uid_to_check = uids[0] if uids else ""

                            if not uid_to_check:
                                clients.send(self.GenResponsMsg("[C][B][FF0000] Invalid or missing Player ID.", sender_id))
                                continue
                            
                            clients.send(self.GenResponsMsg(f"[C][B][FFFF00]✅ Request received! Fetching info for {fix_num(uid_to_check)}...", sender_id))
                            time.sleep(0.5)

                            # Call the new info function
                            info_response = newinfo(uid_to_check)
                            
                            if info_response.get('status') != "ok":
                                clients.send(self.GenResponsMsg("[C][B][FF0000]❌ Wrong ID or API error. Please double-check the ID.", sender_id))
                                continue

                            info = info_response['info']

                            # --- Message 1: Basic Account Info ---
                            player_info_msg = (
                                f"[C][B][00FF00]━━「 Player Information 」━━\n"
                                f"[FFA500]• Name: [FFFFFF]{info.get('AccountName', 'N/A')}\n"
                                f"[FFA500]• Level: [FFFFFF]{info.get('AccountLevel', 'N/A')}\n"
                                f"[FFA500]• Likes: [FFFFFF]{fix_num(info.get('AccountLikes', 0))}\n"
                                f"[FFA500]• UID: [FFFFFF]{fix_num(info.get('accountId', 'N/A'))}\n"
                                f"[FFA500]• Region: [FFFFFF]{info.get('AccountRegion', 'N/A')}"
                            )
                            clients.send(self.GenResponsMsg(player_info_msg, sender_id))
                            time.sleep(0.5)

                            # --- Message 2: Rank and Signature ---
                            rank_info_msg = (
                                f"[C][B][00BFFF]━━「 Rank & Status 」━━\n"
                                f"[FFA500]• BR Rank: [FFFFFF]{info.get('BrMaxRank', 'N/A')} ({info.get('BrRankPoint', 0)} pts)\n"
                                f"[FFA500]• CS Rank: [FFFFFF]{info.get('CsMaxRank', 'N/A')} ({info.get('CsRankPoint', 0)} pts)\n"
                                f"[FFA500]• Bio: [FFFFFF]{info.get('signature', 'No Bio').replace('|', ' ')}"
                            )
                            clients.send(self.GenResponsMsg(rank_info_msg, sender_id))
                            time.sleep(0.5)

                            # --- Message 3: Guild Info (only if the player is in a guild) ---
                            if info.get('GuildID') and info.get('GuildID') != "0":
                                guild_info_msg = (
                                    f"[C][B][FFD700]━━「 Guild Information 」━━\n"
                                    f"[FFA500]• Name: [FFFFFF]{info.get('GuildName', 'N/A')}\n"
                                    f"[FFA500]• ID: [FFFFFF]{fix_num(info.get('GuildID', 'N/A'))}\n"
                                    f"[FFA500]• Members: [FFFFFF]{info.get('GuildMember', 0)}/{info.get('GuildCapacity', 0)}\n"
                                    f"[FFA500]• Level: [FFFFFF]{info.get('GuildLevel', 'N/A')}"
                                )
                                clients.send(self.GenResponsMsg(guild_info_msg, sender_id))
                            else:
                                clients.send(self.GenResponsMsg("[C][B][FFD700]Player is not currently in a guild.", sender_id))

                        except Exception as e:
                            logging.error(f"CRITICAL ERROR in /info command: {e}. Restarting bot.")
                            # Attempt to notify the user of the crash before restarting
                            try:
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                sender_id = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(self.GenResponsMsg("[C][B][FF0000]A critical error occurred. The bot will restart now.", sender_id))
                            except:
                                pass # Ignore if sending the error message also fails
                            restart_program()

                    if "1200" in data.hex()[0:4] and b"/biccco" in data:
                        try:
                            command_split = re.split("/biccco", str(data))
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            sender_id = parsed_data["5"]["data"]["1"]["data"]
                            if len(command_split) <= 1 or not command_split[1].strip():
                                clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter a valid player ID!", sender_id))
                            else:
                                uids = re.findall(r"\b\d{5,15}\b", command_split[1])
                                uid = uids[0] if uids else ""
                                if not uid:
                                    clients.send(self.GenResponsMsg("[C][B][FF0000] Invalid Player ID!", sender_id))
                                else:
                                    info_response = newinfo(uid)
                                    if 'info' not in info_response or info_response['status'] != "ok":
                                        clients.send(self.GenResponsMsg("[C][B] [FF0000] Wrong ID .. Please Check Again", sender_id))
                                    else:
                                        infoo = info_response['info']
                                        basic_info = infoo['basic_info']
                                        bio = basic_info.get('bio', "No bio available").replace("|", " ")
                                        message_info = f"{bio}"
                                        clients.send(self.GenResponsMsg(message_info, sender_id))
                        except Exception as e:
                            logging.error(f"Error processing /biccco command: {e}. Restarting.")
                            restart_program()
#393393993939	                    
                    if "1200" in data.hex()[0:4] and b"/likes" in data:
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}The request is being processed.", uid
                                )
                            )
                            command_split = re.split("/likes", str(data))
                            player_id = command_split[1].split('(')[0].strip()
                            likes_response = send_likes(player_id)
                            message = likes_response['message']
                            clients.send(self.GenResponsMsg(message, uid))
                        except Exception as e:
                            logging.error(f"Error processing /likes command: {e}. Restarting.")
                            restart_program()

                    if "1200" in data.hex()[0:4] and b"/check" in data:
                        try:
                            command_split = re.split("/check", str(data))
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}Checking ban status...", uid
                                )
                            )
                            if len(command_split) > 1:
                                player_id = command_split[1].split('(')[0].strip()
                                banned_status = check_banned_status(player_id)
                                player_id_fixed = fix_num(player_id)
                                status = banned_status.get('status', 'Unknown')
                                player_name = banned_status.get('player_name', 'Unknown')
                                response_message = (
                                    f"{generate_random_color()}Player Name: {player_name}\n"
                                    f"Player ID : {player_id_fixed}\n"
                                    f"Status: {status}"
                                )
                                clients.send(self.GenResponsMsg(response_message, uid))
                        except Exception as e:
                            logging.error(f"Error in /check command: {e}. Restarting.")
                            restart_program()

                    if "1200" in data.hex()[0:4] and b"/help" in data:
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            
                            clients.send(
                                self.GenResponsMsg(
                                        f"""[B][C][FFFF00]✨ BOSS ✨
[FFFFFF]WELCOME! SEE COMMANDS BELOW 👇

""", uid
                                )
                            )
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────[C][B][FFFF00] GROUP COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[00FF00]/🙃3  -> [FFFFFF]3-Player Group
[00FF00]/🙃4  -> [FFFFFF]4-Player Group
[00FF00]/🙃5  -> [FFFFFF]5-Player Group
[00FF00]/🙃6  -> [FFFFFF]6-Player Group
[00FF00]/🙃inv [id] -> [FFFFFF]Invite Any Player""", uid
                                    )
                                )
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────[C][B][FFFF00] SPAM COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[FF4500]/🙃spam [id] -> [FFFFFF]Spam Friend Requests
[FF4500]/🙃x [id] -> [FFFFFF]Spam Invite Requests
[FF4500]/🙃sm [id] -> [FFFFFF]Spam Join Requests
[FF4500]/🙃lag (team) -> [FFFFFF]Lag Any Team """, uid
                                    )
                                )
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────
[C][B][FFFF00] ATTACK / LAG COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[FF0000]/🙃lag (team) 2 -> [FFFFFF]Lag Team Type 2
[FF0000]/🙃attack (team) -> [FFFFFF]Attack Any Team
[FF0000]/🙃start (team) -> [FFFFFF]Force Start a Team""", uid
                                    )
                                )
                            time.sleep(0.5)
                            clients.send(
                                   self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────
[C][B][FFFF00] BADGE COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[00E5FF]/🙃s1 (uid)> [FFFFFF]Moderator Badge
[00E5FF]/🙃s2 (uid)> [FFFFFF]New V-Badge
[00E5FF]/🙃s3 (uid)> [FFFFFF]New V-Badge 2
[00E5FF]/🙃s4 (uid)> [FFFFFF]Small V-Badge
[00E5FF]/🙃s5 (uid)> [FFFFFF]Craftland Badge
[00E5FF]/🙃s6 (uid)> [FFFFFF]Old V-Badge
[00E5FF]/🙃s7 (uid)> [FFFFFF]New V-Badge 3""", uid
                                    )
                                )                                                                
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────
[C][B][FFFF00] EMOTE COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[00FFFF]🙃! (teamcode)-> [FFFFFF]Invite Bot To Your Group
[00FFFF]/🙃e (uid) (emote I'd) -> [FFFFFF]Do Any Emote
[00FFFF]/🙃es (uid) (emote I'd) -> [FFFFFF]Spam Any Emote
[00FFFF]/🙃evo -> [FFFFFF] Incoming""", uid
                                    )
                                )                                                                
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────
[C][B][FFFF00] GENERAL COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[00FF00]
[FF00FF]/🙃info [id] -> [FFFFFF]Player Full Info
[FF00FF]/🙃status [id] -> [FFFFFF]Check Player Status
[FF00FF]/🙃visit [id] -> [FFFFFF]Increase Visitors
[FF00FF]/🙃check [id] -> [FFFFFF]Check Ban Status
[FF00FF]/🙃region -> [FFFFFF]Show Regions""", uid
                                    )
                                )
                            time.sleep(0.5)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]────[FFFFFF]────[FFD700]────
[C][B][FFFF00] EXTRA COMMANDS
[C][B][FFD700]────[FFFFFF]────[FFD700]────

[7CFC00]/🙃biccco [id] -> [FFFFFF]Get Player Bio
[7CFC00]/🙃ai [word] -> [FFFFFF]Ask Bharat AI
[7CFC00]/🙃admin -> [FFFFFF]Know Bot's Admin
[7CFC00]/🙃solo -> [FFFFFF]bot leave the gurup
                               """, uid
                                    )
                                )
                        except Exception as e:
                            logging.error(f"Error processing /help command: {e}. Restarting.")
                            restart_program()
                        

                    if "1200" in data.hex()[0:4] and b"/ai" in data:
                        try:
                            i = re.split("/ai", str(data))[1]
                            if "***" in i:
                                i = i.replace("***", "106")
                            sid = str(i).split("(\\x")[0].strip()
                            headers = {"Content-Type": "application/json"}
                            payload = {
                                "contents": [
                                    {
                                        "parts": [
                                            {"text": sid}
                                        ]
                                    }
                                ]
                            }
                            response = requests.post(
                                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo",
                                headers=headers,
                                json=payload,
                            )
                            if response.status_code == 200:
                                ai_data = response.json()
                                ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                                    self.GenResponsMsg(
                                        ai_response, uid
                                    )
                                )
                            else:
                                logging.error(f"Error with AI API: {response.status_code} {response.text}")
                        except Exception as e:
                            logging.error(f"Error processing /ai command: {e}. Restarting.")
                            restart_program()

# Command changed to /join tc, joins only once, does not leave
                if '1200' in data.hex()[0:4] and b'!' in data:
                    try:
                        # Split the incoming data using the new command '/join tc'
                        split_data = re.split(rb'!', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        
                        # Get the command parts, which should be the room ID
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        # Check if a room ID was provided
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a room code.", uid))
                            continue

                        # The first part of the command is the room ID
                        room_id = command_parts[0]
                        
                        clients.send(
                            self.GenResponsMsg(f"[C][B][32CD32]Attempting to join room: {room_id}", uid)
                        )
                        
                        # Call the join function a single time
                        join_teamcode(socket_client, room_id, key, iv)
                        
                        # Optional: Add a small delay to ensure the join command is processed
                        time.sleep(0.1)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Successfully joined the room.", uid)
                        )
                        

                           
                          
                    except Exception as e:
                        # Updated the error message to reflect the new command name
                        clients.send(self.GenResponsMsg("[C][B][FF0000]Failed To Join Team.", uid))
                        continue


                if '1200' in data.hex()[0:4] and b'/lag' in data:
                    try:
                        split_data = re.split(rb'/lag', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a code.", uid))
                            continue

                        room_id = command_parts[0]
                        repeat_count = 1
                        if len(command_parts) > 1 and command_parts[1].isdigit():
                            repeat_count = int(command_parts[1])
                        if repeat_count > 3:
                            repeat_count = 3
                        
                        clients.send(
                            self.GenResponsMsg(f"[C][B][32CD32]Starting spam process. Will repeat {repeat_count} time(s).", uid)
                        )
                        
                        for i in range(repeat_count):
                            if repeat_count > 1:
                                clients.send(self.GenResponsMsg(f"[C][B][FFA500]Running batch {i + 1} of {repeat_count}...", uid))

                            for _ in range(11111):
                                join_teamcode(socket_client, room_id, key, iv)
                                time.sleep(0.001)
                                leavee = self.leave_s()
                                socket_client.send(leavee)
                                time.sleep(0.0001)
                            
                            if repeat_count > 1 and i < repeat_count - 1:
                                time.sleep(0.1)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Your order has been confirmed", uid)
                        )
                    except Exception as e:
                        logging.error(f"An error occurred during /lag spam: {e}. Restarting.")
                        restart_program()
                if "1200" in data.hex()[0:4] and b"/solo" in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][00FF00] Exited from the group. ", uid
                            )
                        )
                    except Exception as e:
                        logging.error(f"Error processing /solo command: {e}. Restarting.")
                        restart_program()
                if '1200' in data.hex()[0:4] and b'/attack' in data:
                    try:
                        split_data = re.split(rb'/attack', data)
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]With this, you can join and attack any group \n/attack [TeamCode]", uid))
                            continue

                        team_code = command_parts[0]
                        clients.send(
                            self.GenResponsMsg(f"[C][B][FFA500]Join attack has started on Team Code {team_code}...", uid)
                        )

                        start_packet = self.start_autooo()
                        leave_packet = self.leave_s()
                        attack_start_time = time.time()
                        while time.time() - attack_start_time < 45:
                            join_teamcode(socket_client, team_code, key, iv)
                            socket_client.send(start_packet)
                            socket_client.send(leave_packet)
                            time.sleep(0.15)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Double attack on the team is complete! ✅   {team_code}!", uid)
                        )

                    except Exception as e:
                        logging.error(f"An error occurred in /attack command: {e}. Restarting.")
                        restart_program()
                
                
                if "1200" in data.hex()[0:4] and b'/e' in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Command format: @a <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'/e')[1].split(b'(')[0].decode().strip().split()
                        if len(command_parts) < 1:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: @a <target_id> <emote_id>", uid_sender))
                            continue

                        e_choice = command_parts[-1]
                        target_ids = [uid_sender]
                        
                        
                        
                        e_emotes = {
    "1":   "909000001",
    "lol":   "909000002",
    "3":   "909000003",
    "4":   "909000004",
    "5":   "909000005",
    "6":   "909000006",
    "7":   "909000007",
    "8":   "909000008",
    "9":   "909000009",
    "10":  "909000010",
    "11":  "909000011",
    "12":  "909000012",
    "13":  "909000013",
    "14":  "909000014",
    "15":  "909000015",
    "16":  "909000016",
    "17":  "909000017",
    "18":  "909000018",
    "19":  "909000019",
    "20":  "909000020",
    "21":  "909000021",
    "22":  "909000022",
    "23":  "909000023",
    "24":  "909000024",
    "25":  "909000025",
    "26":  "909000026",
    "27":  "909000027",
    "28":  "909000028",
    "29":  "909000029",
    "30":  "909000031",
    "31":  "909000032",
    "32":  "909000033",
    "33":  "909000034",
    "34":  "909000035",
    "35":  "909000036",
    "36":  "909000037",
    "37":  "909000038",
    "38":  "909000039",
    "39":  "909000040",
    "40":  "909000041",
    "41":  "909000042",
    "42":  "909000043",
    "43":  "909000044",
    "44":  "909000045",
    "45":  "909000046",
    "46":  "909000047",
    "47":  "909000048",
    "48":  "909000049",
    "49":  "909000051",
    "50":  "909000052",
    "51":  "909000053",
    "52":  "909000054",
    "53":  "909000055",
    "54":  "909000056",
    "55":  "909000057",
    "56":  "909000058",
    "57":  "909000059",
    "58":  "909000060",
    "59":  "909000061",
    "60":  "909000062",
    "61":  "909000063",
    "62":  "909000064",
    "63":  "909000065",
    "64":  "909000066",
    "65":  "909000067",
    "66":  "909000068",
    "67":  "909000069",
    "68":  "909000070",
    "69":  "909000071",
    "70":  "909000072",
    "71":  "909000073",
    "72":  "909000074",
    "73":  "909000075",
    "74":  "909000076",
    "75":  "909000077",
    "76":  "909000078",
    "77":  "909000079",
    "78":  "909000080",
    "79":  "909000081",
    "80":  "909000082",
    "81":  "909000083",
    "82":  "909000084",
    "83":  "909000085",
    "84":  "909000086",
    "85":  "909000087",
    "86":  "909000088",
    "87":  "909000089",
    "88":  "909000090",
    "89":  "909000091",
    "90":  "909000092",
    "91":  "909000093",
    "92":  "909000094",
    "93":  "909000095",
    "94":  "909000096",
    "95":  "909000097",

    "106": "909000108",
    "119": "909000121",
    "120": "909000122",
    "121": "909000123",
    "122": "909000124",
    "123": "909000125",
    "124": "909000126",
    "125": "909000127",
    "126": "909000128",
    "127": "909000129",
    "128": "909000130",
    "129": "909000131",
    "130": "909000132",
    "131": "909000133",
    "132": "909000134",
    "133": "909000135",
    "134": "909000136",
    "135": "909000137",
    "136": "909000138",
    "137": "909000139",
    "138": "909000140",
    "139": "909000141",
    "140": "909000142",

    "142": "909000144",
    "143": "909000145",
    "144": "909000150",

    "145": "909033001",
    "146": "909033002",
    "147": "909033003",
    "148": "909033004",
    "149": "909033005",
    "150": "909033006",
    "151": "909033007",
    "152": "909033008",
    "153": "909033009",
    "154": "909033010",

    "155": "909034001",
    "156": "909034002",
    "157": "909034003",
    "158": "909034004",
    "159": "909034005",
    "160": "909034006",
    "161": "909034007",
    "162": "909034008",
    "163": "909034009",
    "164": "909034010",
    "165": "909034011",
    "166": "909034012",
    "167": "909034013",
    "168": "909034014",

    "169": "909035001",

    "173": "909035005",
    "174": "909035006",
    "175": "909035007",
    "176": "909035008",
    "177": "909035009",
    "178": "909035010",
    "179": "909035011",
    "180": "909035012",
    "181": "909035013",
    "182": "909035014",
    "183": "909035015",

    "184": "909036001",
    "185": "909036002",
    "186": "909036003",
    "187": "909036004",
    "188": "909036005",
    "189": "909036006",
    "190": "909036008",
    "191": "909036009",
    "192": "909036010",
    "193": "909036011",
    "194": "909036012",
    "195": "909036014",

    "196": "909037001",
    "197": "909037002",
    "198": "909037003",
    "199": "909037004",
    "200": "909037005",
    "201": "909037006",
    "202": "909037007",
    "203": "909037008",
    "204": "909037009",
    "205": "909037010",
    "206": "909037011",
    "207": "909037012",

    "208": "909038001",
    "210": "909038003",
    "211": "909038004",
    "212": "909038005",
    "213": "909038006",
    "214": "909038008",
    "215": "909038009",
    "216": "909038010",
    "217": "909038011",
    "218": "909038012",
    "219": "909038013",

    "220": "909039001",
    "221": "909039002",
    "222": "909039003",
    "223": "909039004",
    "224": "909039005",
    "225": "909039006",
    "226": "909039007",
    "227": "909039008",
    "228": "909039009",
    "229": "909039010",
    "230": "909039011",
    "231": "909039012",
    "232": "909039013",
    "233": "909039014",

    "234": "909040001",
    "235": "909040002",
    "236": "909040003",
    "237": "909040004",
    "238": "909040005",
    "239": "909040006",
    "240": "909040008",
    "241": "909040009",
    "242": "909040010",
    "243": "909040011",
    "244": "909040012",
    "245": "909040013",

    "247": "909041001",
    "248": "909041002",
    "249": "909041003",
    "250": "909041004",
    "251": "909041005",
    "252": "909041006",
    "253": "909041007",
    "254": "909041008",
    "255": "909041009",
    "256": "909041010",
    "257": "909041011",
    "258": "909041012",
    "259": "909041013",
    "260": "909041014",
    "261": "909041015",

    "262": "909042001",
    "263": "909042002",
    "264": "909042003",
    "265": "909042004",
    "266": "909042005",
    "267": "909042006",
    "lvl100": "909042007",
    "100lvl": "909042007",
    "100": "909042007",
    "269": "909042008",
    "270": "909042009",
    "271": "909042011",
    "272": "909042012",
    "274": "909042016",
    "275": "909042017",
    "276": "909042018",

    "277": "909043001",
    "278": "909043002",
    "279": "909043003",
    "280": "909043004",
    "281": "909043005",
    "282": "909043006",
    "283": "909043007",
    "284": "909043008",
    "285": "909043009",

    "288": "909044001",
    "289": "909044002",
    "290": "909044003",
    "291": "909044004",
    "292": "909044005",
    "294": "909044007",
    "295": "909044008",
    "296": "909044009",
    "297": "909044010",
    "298": "909044011",
    "299": "909044012",
    "300": "909044015",
    "301": "909044016",

    "302": "909045001",
    "303": "909045002",
    "304": "909045003",
    "305": "909045004",
    "306": "909045005",
    "307": "909045006",
    "308": "909045007",
    "309": "909045008",
    "310": "909045009",
    "311": "909045010",
    "312": "909045011",
    "314": "909045015",
    "315": "909045016",
    
    "316": "909045017",
    "317": "909046001",
    "318": "909046002",
    "319": "909046003",
    "322": "909046006",
    "323": "909046007",
    "324": "909046008",
    "325": "909046009",
    "326": "909046010",
    "327": "909046011",
    "328": "909046012",
    "329": "909046013",
    "330": "909046014",
    "331": "909046015",
    "332": "909046016",
    "333": "909046017",
    "334": "909047001",
    "337": "909047004",
    "338": "909047005",
    "339": "909047006",
    "340": "909047007",
    "341": "909047008",
    "342": "909047009",
    "343": "909047010",
    "344": "909047011",
    "345": "909047012",
    "346": "909047013",
    "347": "909047015",
    "348": "909047016",
    "349": "909047017",
    "350": "909047018",
    "351": "909047019",
    "353": "909048002",
    "354": "909048003",
    "355": "909048004",
    "356": "909048005",
    "357": "909048006",
    "358": "909048007",
    "359": "909048008",
    "361": "909048010",
    "362": "909048011",
    "363": "909048012",
    "364": "909048013",
    "365": "909048014",
    "366": "909048015",
    "367": "909048016",
    "368": "909048017",
    "369": "909048018",
    "370": "909049001",
    "371": "909049002",
    "372": "909049003",
    "373": "909049004",
    "374": "909049005",
    "375": "909049006",
    "376": "909049007",
    "378": "909049009",
    "379": "909049010",
    "380": "909049011",
    "381": "909049012",
    "382": "909049013",
    "383": "909049014",
    "384": "909049015",
    "385": "909049016",
    "386": "909049017",
    "387": "909049018",
    "388": "909049019",
    "389": "909049020",
    "390": "909049021",
    "391": "909050002",
    "393": "909050004",
    "394": "909050005",
    "395": "909050006",
    "396": "909050008",
    "ring": "909050009",
    "398": "909050010",
    "399": "909050011",
    "400": "909050012",
    "401": "909050013",
    "402": "909050014",
    "403": "909050015",
    "404": "909050016",
    "405": "909050017",
    "406": "909050018",
    "407": "909050019",
    "408": "909050020",
    "409": "909050021",

    "410": "909046004",
    "411": "909046005",
    "412": "909047002",
    "413": "909047003",
    "414": "909048001",
    "415": "909048009",
    "416": "909049008",
    "417": "909050003",
    
    "p90": "909049010",
    "m60": "909051003",
    "mp5": "909033002",
    "groza": "909041005",
    "thompson_evo": "909038010",
    "m10_red": "909039011",
    "mp40_blue": "909040010",
    "m10_green": "909000081",
    "xm8": "909000085",
    "ak": "909000063",
    "mp40": "909000075",
    "m4a1": "909033001",
    "famas": "909000090",
    "scar": "909000068",
    "ump": "909000098",
    "m18": "909035007",
    "fist": "909037011",
    "g18": "909038012",
    "an94": "909035012",
    "woodpecker": "909042008",

    "money": "909000055",
    "paisa": "909000055",
    "heart": "909000045",
    "love": "909000045",
    "rose": "909000010",
    "throne": "909000014",
    "pirate": "909000034",
    "flag": "909000034",
    "car": "909000039",
    "dust": "909000039",
    "lol": "909000002",
    "laugh": "909000002",
    "cobra": "909000072",
    "ghost": "909036001",
    "fire": "909033001",
    "sholay": "909050020",
    "blade": "909050013",
    "sword": "909050013",

    "hello": "909000001",
    "hi": "909000001",
    "dab": "909000005",
    "chicken": "909000006",
    "dance": "909000008",
    "babyshark": "909000009",
    "pushup": "909000012",
    "dragon": "909000015",
    "highfive": "909000025",
    "selfie": "909000032",
    "breakdance": "909000040",
    "kungfu": "909000041",

    "thor": "909050008",
    "rasengan": "909047015",
    "ninja": "909047018",
    "clone": "909047019",
    "fireball": "909050005",
    "hammer": "909050008",

    "provoke": "909000003",
    "applause": "909000004",
    "armwave": "909000007",
    "puffyride": "909051014",
    "circle": "909050009",
    "petals": "909051013",
    "bow": "909051012",
    "motorbike": "909051010",
    "shower": "909051004",
    "dream": "909051002",
    "angelic": "909051001",
    "paint": "909048015",
    "flar": "909041008",
    "owl": "909049003",
    "bigdill": "909049001",
    "csgm": "909041013",
    "mapread": "909050014",
    "tomato": "909050015",
    "ninjasummon": "909050002",
    "lvl100": "909042007",
    "100": "909042007",
    "auraboat": "909050028",
    "flyingguns": "909049012",
    "iheartyou": "909000045",
    "pirateflag": "909000034",
    "valentineheart": "909038004",
    "rampagebook": "909034001",
    "guildflag": "909049017",
    "fish": "909040004",
    "inosuke": "909041003",
    "shootdance": "909000008",
    "flowrs": "909000010",
    "mummydance": "909000011",
    "shuffling": "909000013",
    "dragonfist": "909000015",
    "dangerousgame": "909000016",
    "jaguardance": "909000017",
    "threaten": "909000018",
    "shakewithme": "909000019",
    "devilsmove": "909000020",
    "furiousslam": "909000021",
    "moonflip": "909000022",
    "wigglewalk": "909000023",
    "battledance": "909000024",
    "shakeitup": "909000026",
    "gloriousspin": "909000027",
    "cranekick": "909000028",
    "partydance": "909000029",
    "jigdance": "909000031",
    "soulshaking": "909000033",
    "healingdance": "909000035",
    "topdj": "909000036",
    "deathglare": "909000037",
    "powerofmoney": "909000038",
    "eatmydust": "909000039",
    "bonappetit": "909000042",
    "aimfire": "909000043",
    "swan": "909000044",
    "teatime": "909000046",
    "bringiton": "909000047",
    "whyohwhy": "909000048",
    "fancyhands": "909000049",
    "shimmy": "909000051",
    "doggie": "909000052",
    "challengeon": "909000053",
    "lasso": "909000054",
    "imrich": "909000055",
    "morepractice": "909000079",
    "ffws2021": "909000080",
    "dracossoul": "909000081",
    "goodgame": "909000082",
    "greetings": "909000083",
    "walker": "909000084",
    "bornoflight": "909000085",
    "mythosfour": "909000086",
    "championgrab": "909000087",
    "winandchill": "909000088",
    "hadouken": "909000089",
    "bloodwraith": "909000090",
    "bigsmash": "909000091",
    "fancysteps": "909000092",
    "allincontrol": "909000093",
    "debugging": "909000094",
    "waggorwave": "909000095",
    "crazyguitar": "909000096",
    "poof": "909000097",
    "chosenvictor": "909000098",
    "challenger": "909000099",
    "partygame5": "909000100",
    "partygame6": "909000101",
    "partygame3": "909000102",
    "partygame4": "909000103",
    "partygame7": "909000104",
    "partygame1": "909000105",
    "partygame8": "909000106",
    "partygame2": "909000107",
    "dribbleking": "909000121",
    "ffwsguitar": "909000122",
    "mindit": "909000123",
    "goldencombo": "909000124",
    "sickmoves": "909000125",
    "rapswag": "909000126",
    "battleinstyle": "909000127",
    "rulersflag": "909000128",
    "moneythrow": "909000129",
    "endlessbullets": "909000130",
    "smoothsway": "909000131",
    "number1": "909000132",
    "fireslam": "909000133",
    "heartbroken": "909000134",
    "rockpaperscissors": "909000135",
    "shatteredreality": "909000136",
    "haloofmusic": "909000137",
    "burntbbq": "909000138",
    "switchingsteps": "909000139",
    "creedslay": "909000140",
    "leapoffail": "909000141",
    "rhythmgirl": "909000142",
    "helicoptership": "909000143",
    "kungfutigers": "909000144",
    "possessedwarrior": "909000145",
    "raiseyourthumb": "909000150",

    "fireborn": "909033001",
    "goldenfeather": "909033002",
    "comeanddance": "909033003",
    "dropkick": "909033004",
    "sitdown": "909033005",
    "booyahsparks": "909033006",
    "ffwsdance": "909033007",
    "easypeasy": "909033008",
    "winnerthrow": "909033009",
    "weightofvictory": "909033010",

    "chronicle": "909034001",
    "collapse": "909034002",
    "flaminggroove": "909034003",
    "energetic": "909034004",
    "ridicule": "909034005",
    "teasewaggor": "909034006",
    "greatconductor": "909034007",
    "fakedeath": "909034008",
    "twerk": "909034009",
    "brheroic": "909034010",
    "brmaster": "909034011",
    "csheroic": "909034012",
    "csmaster": "909034013",
    "yesido": "909034014",

    "freemoney": "909035001",
    "singersb03": "909035002",
    "singersb0203": "909035003",
    "singersb010203": "909035004",
    "victoriouseagle": "909035005",
    "flyingsaucer": "909035006",
    "weaponmagician": "909035007",
    "bobbledance": "909035008",
    "weighttraining": "909035009",
    "beautifullove": "909035010",
    "groovemoves": "909035011",
    "howlersrage": "909035012",
    "louderplease": "909035013",
    "ninjastand": "909035014",
    "creatorinaction": "909035015",

    "ghostfloat": "909036001",
    "shibasurf": "909036002",
    "waiterwalk": "909036003",
    "grafficameraman": "909036004",
    "agileboxer": "909036005",
    "sunbathing": "909036006",
    "skateboardswag": "909036008",
    "phantomtamer": "909036009",
    "signal": "909036010",
    "eternaldescent": "909036011",
    "swaggydance": "909036012",
    "admire": "909036014",

    "reindeerfloat": "909037001",
    "bamboodance": "909037002",
    "constellationdance": "909037003",
    "trophygrab": "909037004",
    "starryhands": "909037005",
    "yum": "909037006",
    "happydancing": "909037007",
    "juggle": "909037008",
    "neonsign": "909037009",
    "beasttease": "909037010",
    "drachentear": "909037011",
    "clapdance": "909037012",

    "influencer": "909038001",
    "macarena": "909038002",
    "technoblast": "909038003",
    "valentine": "909038004",
    "angrywalk": "909038005",
    "makesomenoise": "909038006",
    "crocohooray": "909038008",
    "scorpionspin": "909038009",
    "cindersummon": "909038010",
    "shallwedance": "909038011",
    "spinmaster": "909038013",

    "festival": "909039001",
    "artisticdance": "909039002",
    "forwardbackward": "909039003",
    "scorpionfriend": "909039004",
    "achingpower": "909039005",
    "earthlyforce": "909039006",
    "grenademagic": "909039007",
    "ohyeah": "909039008",
    "graceonwheels": "909039009",
    "flex": "909039010",
    "firebeasttamer": "909039012",
    "crimsontunes": "909039013",
    "swaggyvsteps": "909039014",

    "chromaticfinish": "909040001",
    "smashthefeather": "909040002",
    "sonoroussteps": "909040003",
    "chromaticpop": "909040005",
    "chromatwist": "909040006",
    "birthofjustice": "909040008",
    "spidersense": "909040009",
    "chromasonicshot": "909040010",
    "playwiththunderbolt": "909040011",
    "anniversary": "909040012",
    "wisdomswing": "909040013",

    "thunderflash": "909041001",
    "whirlpool": "909041002",
    "flyinginksword": "909041004",
    "dancepuppet": "909041006",
    "highknees": "909041007",
    "feeltheelectricity": "909041009",
    "whacacotton": "909041010",
    "honorablemention": "909041011",
    "brgrandmaster": "909041012",
    "monsterclubbing": "909041014",
    "basudaradance": "909041015",

    "stirfryfrostfire": "909042001",
    "moneyrain": "909042002",
    "frostfirecalling": "909042003",
    "stompingfoot": "909042004",
    "thisway": "909042005",
    "excellentservice": "909042006",
    "realtiger": "909042008",
    "celebrationschuss": "909042009",
    "dawnvoyage": "909042011",
    "lamborghiniride": "909042012",
    "toiletman": "909042013",
    "handgrooves": "909042016",
    "kemusan": "909042018",

    "ribbitrider": "909043001",
    "innerself": "909043002",
    "emperortreasure": "909043003",
    "whysochaos": "909043004",
    "hugefeast": "909043005",
    "colorburst": "909043006",
    "dragonswipe": "909043007",
    "samba": "909043008",
    "speedsummon": "909043009",
    "whatamatch": "909043010",
    "whatapair": "909043013",

    "bytemounting": "909044001",
    "unicyclist": "909044002",
    "basketrafting": "909044003",
    "happylamb": "909044004",
    "paradox": "909044005",
    "harmoniousparadox": "909044006",
    "raiseyourthumb2": "909044007",
    "claphands": "909044008",
    "donedeal": "909044009",
    "starcatcher": "909044010",
    "paradoxwings": "909044011",
    "zombified": "909044012",
    "honkup": "909044016",

    "cyclone": "909045001",
    "springrocker": "909045002",
    "giddyup": "909045003",
    "goosydance": "909045004",
    "captainvictor": "909045005",
    "youknowimgood": "909045006",
    "stepstep": "909045007",
    "superyay": "909045008",
    "moonwalk": "909045009",
    "flowersalute": "909045010",
    "foxyrun": "909045011",
    "waggorsseesaw": "909045012",
    "floatingmeditation": "909045015",
    "naatunaatu": "909045016",
    "championswalk": "909045017",

    "auraboarder": "909046001",
    "booyahchamp": "909046002",
    "controlledcombustion": "909046003",
    "cheerstovictory": "909046004",
    "shoeshining": "909046005",
    "gunspinning": "909046006",
    "crowdpleaser": "909046007",
    "nosweat": "909046008",
    "magmaquake": "909046009",
    "maxfirepower": "909046010",
    "canttouchthis": "909046011",
    "firestarter": "909046012",
    "ffwsflag": "909046013",
    "beatdrop": "909046014",
    "spatialawareness": "909046015",
    "trapping": "909046016",
    "soaringup": "909046017",

    "wontbowdown": "909047001",
    "aurora": "909047002",
    "couchfortwo": "909047003",
    "flutterdash": "909047004",
    "slipperythrone": "909047005",
    "acceptancespeech": "909047006",
    "lovemelovemenot": "909047007",
    "scissorsavvy": "909047008",
    "thinker": "909047009",
    "matchcountdown": "909047010",
    "hiptwists": "909047011",
    "jkt48": "909047012",
    "stormyascent": "909047013",
    "thousandyears": "909047016",
    "ninjasign": "909047017",
    "ninjarun": "909047018",
    "clonejutsu": "909047019",

    "rescue": "909048001",
    "midnightperuse": "909048002",
    "guitargroove": "909048003",
    "keyboardplayer": "909048004",
    "ondrums": "909048005",
    "chacchac": "909048006",
    "pillowfight": "909048007",
    "targetpractice": "909048008",
    "goofycamel": "909048009",
    "hitasix": "909048010",
    "flagsummon": "909048011",
    "swiftsteps": "909048012",
    "carnivalfunk": "909048013",
    "slurp": "909048014",
    "halftime": "909048016",
    "throwin": "909048017",
    "bailalorocky": "909048018",

    "handraise": "909049002",
    "slapandtwist": "909049004",
    "sidewiggle": "909049005",
    "creationdays": "909049006",
    "rainingcoins": "909049007",
    "clapclaphooray": "909049008",
    "infiniteloops": "909049009",
    "p90surfer": "909049010",
    "boxingmachine": "909049011",
    "comicbarf": "909049013",
    "driveby": "909049014",
    "pedalmetal": "909049015",
    "spearspin": "909049016",
    "discodazzle": "909049018",
    "squatchallenge": "909049019",
    "winninggoal": "909049020",
    "headhigh": "909049021",

    "finalbattle": "909050003",
    "foreheadpoke": "909050004",
    "fireballjutsu": "909050005",
    "flyingraijin": "909050006",
    "drumtwirl": "909050010",
    "bunnyaction": "909050011",
    "broomswoosh": "909050012",
    "bladefromheart": "909050013",
    "tacticalmoveout": "909050016",
    "bunnywiggle": "909050017",
    "flamingheart": "909050018",
    "rainorshine": "909050019",
    "peakpoints": "909050021",

    "bow": "909051012",
    "petals": "909051013",
    "puffyride": "909051014"
}
                        


                        emote_id = e_emotes.get(e_choice)
                        
                        
                        if not emote_id:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Invalid choice: {e_choice}. Please use a number from 1-417.", uid_sender))
                            continue
                        
                        

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Activating emote {emote_id} for {len(target_ids)} player(s)...", uid_sender))

                        for target_id in target_ids:
                            
                            emote_packet = self.send_emote(target_id, emote_id)
                            socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.1) # Small delay between packets
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote command finished!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing @a command: {e}")
                        try:
                            emote_packet = self.send_emote(target_id, emote_id)
                            socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.1) # Small delay between packets
                        except:
                            pass             
                            
                               
                                  
                if "1200" in data.hex()[0:4] and b'/t' in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Command format: @a <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'/t')[1].split(b'(')[0].decode().strip().split()
                        if len(command_parts) < 1:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: @a <target_id> <emote_id>", uid_sender))
                            continue

                        e_choice = command_parts[-1]
                        target_ids = [uid_sender]
                        
                        
                        
                        
                        e_emotes = {
    "1":   "909000001",
    "lol":   "909000002",
    "3":   "909000003",
    "4":   "909000004",
    "5":   "909000005",
    "6":   "909000006",
    "7":   "909000007",
    "8":   "909000008",
    "9":   "909000009",
    "10":  "909000010",
    "11":  "909000011",
    "12":  "909000012",
    "13":  "909000013",
    "14":  "909000014",
    "15":  "909000015",
    "16":  "909000016",
    "17":  "909000017",
    "18":  "909000018",
    "19":  "909000019",
    "20":  "909000020",
    "21":  "909000021",
    "22":  "909000022",
    "23":  "909000023",
    "24":  "909000024",
    "25":  "909000025",
    "26":  "909000026",
    "27":  "909000027",
    "28":  "909000028",
    "29":  "909000029",
    "30":  "909000031",
    "31":  "909000032",
    "32":  "909000033",
    "33":  "909000034",
    "34":  "909000035",
    "35":  "909000036",
    "36":  "909000037",
    "37":  "909000038",
    "38":  "909000039",
    "39":  "909000040",
    "40":  "909000041",
    "41":  "909000042",
    "42":  "909000043",
    "43":  "909000044",
    "44":  "909000045",
    "45":  "909000046",
    "46":  "909000047",
    "47":  "909000048",
    "48":  "909000049",
    "49":  "909000051",
    "50":  "909000052",
    "51":  "909000053",
    "52":  "909000054",
    "53":  "909000055",
    "54":  "909000056",
    "55":  "909000057",
    "56":  "909000058",
    "57":  "909000059",
    "58":  "909000060",
    "59":  "909000061",
    "60":  "909000062",
    "61":  "909000063",
    "62":  "909000064",
    "63":  "909000065",
    "64":  "909000066",
    "65":  "909000067",
    "66":  "909000068",
    "67":  "909000069",
    "68":  "909000070",
    "69":  "909000071",
    "70":  "909000072",
    "71":  "909000073",
    "72":  "909000074",
    "73":  "909000075",
    "74":  "909000076",
    "75":  "909000077",
    "76":  "909000078",
    "77":  "909000079",
    "78":  "909000080",
    "79":  "909000081",
    "80":  "909000082",
    "81":  "909000083",
    "82":  "909000084",
    "83":  "909000085",
    "84":  "909000086",
    "85":  "909000087",
    "86":  "909000088",
    "87":  "909000089",
    "88":  "909000090",
    "89":  "909000091",
    "90":  "909000092",
    "91":  "909000093",
    "92":  "909000094",
    "93":  "909000095",
    "94":  "909000096",
    "95":  "909000097",

    "106": "909000108",
    "119": "909000121",
    "120": "909000122",
    "121": "909000123",
    "122": "909000124",
    "123": "909000125",
    "124": "909000126",
    "125": "909000127",
    "126": "909000128",
    "127": "909000129",
    "128": "909000130",
    "129": "909000131",
    "130": "909000132",
    "131": "909000133",
    "132": "909000134",
    "133": "909000135",
    "134": "909000136",
    "135": "909000137",
    "136": "909000138",
    "137": "909000139",
    "138": "909000140",
    "139": "909000141",
    "140": "909000142",

    "142": "909000144",
    "143": "909000145",
    "144": "909000150",

    "145": "909033001",
    "146": "909033002",
    "147": "909033003",
    "148": "909033004",
    "149": "909033005",
    "150": "909033006",
    "151": "909033007",
    "152": "909033008",
    "153": "909033009",
    "154": "909033010",

    "155": "909034001",
    "156": "909034002",
    "157": "909034003",
    "158": "909034004",
    "159": "909034005",
    "160": "909034006",
    "161": "909034007",
    "162": "909034008",
    "163": "909034009",
    "164": "909034010",
    "165": "909034011",
    "166": "909034012",
    "167": "909034013",
    "168": "909034014",

    "169": "909035001",

    "173": "909035005",
    "174": "909035006",
    "175": "909035007",
    "176": "909035008",
    "177": "909035009",
    "178": "909035010",
    "179": "909035011",
    "180": "909035012",
    "181": "909035013",
    "182": "909035014",
    "183": "909035015",

    "184": "909036001",
    "185": "909036002",
    "186": "909036003",
    "187": "909036004",
    "188": "909036005",
    "189": "909036006",
    "190": "909036008",
    "191": "909036009",
    "192": "909036010",
    "193": "909036011",
    "194": "909036012",
    "195": "909036014",

    "196": "909037001",
    "197": "909037002",
    "198": "909037003",
    "199": "909037004",
    "200": "909037005",
    "201": "909037006",
    "202": "909037007",
    "203": "909037008",
    "204": "909037009",
    "205": "909037010",
    "206": "909037011",
    "207": "909037012",

    "208": "909038001",
    "210": "909038003",
    "211": "909038004",
    "212": "909038005",
    "213": "909038006",
    "214": "909038008",
    "215": "909038009",
    "216": "909038010",
    "217": "909038011",
    "218": "909038012",
    "219": "909038013",

    "220": "909039001",
    "221": "909039002",
    "222": "909039003",
    "223": "909039004",
    "224": "909039005",
    "225": "909039006",
    "226": "909039007",
    "227": "909039008",
    "228": "909039009",
    "229": "909039010",
    "230": "909039011",
    "231": "909039012",
    "232": "909039013",
    "233": "909039014",

    "234": "909040001",
    "235": "909040002",
    "236": "909040003",
    "237": "909040004",
    "238": "909040005",
    "239": "909040006",
    "240": "909040008",
    "241": "909040009",
    "242": "909040010",
    "243": "909040011",
    "244": "909040012",
    "245": "909040013",

    "247": "909041001",
    "248": "909041002",
    "249": "909041003",
    "250": "909041004",
    "251": "909041005",
    "252": "909041006",
    "253": "909041007",
    "254": "909041008",
    "255": "909041009",
    "256": "909041010",
    "257": "909041011",
    "258": "909041012",
    "259": "909041013",
    "260": "909041014",
    "261": "909041015",

    "262": "909042001",
    "263": "909042002",
    "264": "909042003",
    "265": "909042004",
    "266": "909042005",
    "267": "909042006",
    "lvl100": "909042007",
    "100lvl": "909042007",
    "100": "909042007",
    "269": "909042008",
    "270": "909042009",
    "271": "909042011",
    "272": "909042012",
    "274": "909042016",
    "275": "909042017",
    "276": "909042018",

    "277": "909043001",
    "278": "909043002",
    "279": "909043003",
    "280": "909043004",
    "281": "909043005",
    "282": "909043006",
    "283": "909043007",
    "284": "909043008",
    "285": "909043009",

    "288": "909044001",
    "289": "909044002",
    "290": "909044003",
    "291": "909044004",
    "292": "909044005",
    "294": "909044007",
    "295": "909044008",
    "296": "909044009",
    "297": "909044010",
    "298": "909044011",
    "299": "909044012",
    "300": "909044015",
    "301": "909044016",

    "302": "909045001",
    "303": "909045002",
    "304": "909045003",
    "305": "909045004",
    "306": "909045005",
    "307": "909045006",
    "308": "909045007",
    "309": "909045008",
    "310": "909045009",
    "311": "909045010",
    "312": "909045011",
    "314": "909045015",
    "315": "909045016",
    
    "316": "909045017",
    "317": "909046001",
    "318": "909046002",
    "319": "909046003",
    "322": "909046006",
    "323": "909046007",
    "324": "909046008",
    "325": "909046009",
    "326": "909046010",
    "327": "909046011",
    "328": "909046012",
    "329": "909046013",
    "330": "909046014",
    "331": "909046015",
    "332": "909046016",
    "333": "909046017",
    "334": "909047001",
    "337": "909047004",
    "338": "909047005",
    "339": "909047006",
    "340": "909047007",
    "341": "909047008",
    "342": "909047009",
    "343": "909047010",
    "344": "909047011",
    "345": "909047012",
    "346": "909047013",
    "347": "909047015",
    "348": "909047016",
    "349": "909047017",
    "350": "909047018",
    "351": "909047019",
    "353": "909048002",
    "354": "909048003",
    "355": "909048004",
    "356": "909048005",
    "357": "909048006",
    "358": "909048007",
    "359": "909048008",
    "361": "909048010",
    "362": "909048011",
    "363": "909048012",
    "364": "909048013",
    "365": "909048014",
    "366": "909048015",
    "367": "909048016",
    "368": "909048017",
    "369": "909048018",
    "370": "909049001",
    "371": "909049002",
    "372": "909049003",
    "373": "909049004",
    "374": "909049005",
    "375": "909049006",
    "376": "909049007",
    "378": "909049009",
    "379": "909049010",
    "380": "909049011",
    "381": "909049012",
    "382": "909049013",
    "383": "909049014",
    "384": "909049015",
    "385": "909049016",
    "386": "909049017",
    "387": "909049018",
    "388": "909049019",
    "389": "909049020",
    "390": "909049021",
    "391": "909050002",
    "393": "909050004",
    "394": "909050005",
    "395": "909050006",
    "396": "909050008",
    "ring": "909050009",
    "398": "909050010",
    "399": "909050011",
    "400": "909050012",
    "401": "909050013",
    "402": "909050014",
    "403": "909050015",
    "404": "909050016",
    "405": "909050017",
    "406": "909050018",
    "407": "909050019",
    "408": "909050020",
    "409": "909050021",

    "410": "909046004",
    "411": "909046005",
    "412": "909047002",
    "413": "909047003",
    "414": "909048001",
    "415": "909048009",
    "416": "909049008",
    "417": "909050003",
    
    "p90": "909049010",
    "m60": "909051003",
    "mp5": "909033002",
    "groza": "909041005",
    "thompson_evo": "909038010",
    "m10_red": "909039011",
    "mp40_blue": "909040010",
    "m10_green": "909000081",
    "xm8": "909000085",
    "ak": "909000063",
    "mp40": "909000075",
    "m4a1": "909033001",
    "famas": "909000090",
    "scar": "909000068",
    "ump": "909000098",
    "m18": "909035007",
    "fist": "909037011",
    "g18": "909038012",
    "an94": "909035012",
    "woodpecker": "909042008",

    "money": "909000055",
    "paisa": "909000055",
    "heart": "909000045",
    "love": "909000045",
    "rose": "909000010",
    "throne": "909000014",
    "pirate": "909000034",
    "flag": "909000034",
    "car": "909000039",
    "dust": "909000039",
    "lol": "909000002",
    "laugh": "909000002",
    "cobra": "909000072",
    "ghost": "909036001",
    "fire": "909033001",
    "sholay": "909050020",
    "blade": "909050013",
    "sword": "909050013",

    "hello": "909000001",
    "hi": "909000001",
    "dab": "909000005",
    "chicken": "909000006",
    "dance": "909000008",
    "babyshark": "909000009",
    "pushup": "909000012",
    "dragon": "909000015",
    "highfive": "909000025",
    "selfie": "909000032",
    "breakdance": "909000040",
    "kungfu": "909000041",

    "thor": "909050008",
    "rasengan": "909047015",
    "ninja": "909047018",
    "clone": "909047019",
    "fireball": "909050005",
    "hammer": "909050008",

    "provoke": "909000003",
    "applause": "909000004",
    "armwave": "909000007",
    "puffyride": "909051014",
    "circle": "909050009",
    "petals": "909051013",
    "bow": "909051012",
    "motorbike": "909051010",
    "shower": "909051004",
    "dream": "909051002",
    "angelic": "909051001",
    "paint": "909048015",
    "flar": "909041008",
    "owl": "909049003",
    "bigdill": "909049001",
    "csgm": "909041013",
    "mapread": "909050014",
    "tomato": "909050015",
    "ninjasummon": "909050002",
    "lvl100": "909042007",
    "100": "909042007",
    "auraboat": "909050028",
    "flyingguns": "909049012",
    "iheartyou": "909000045",
    "pirateflag": "909000034",
    "valentineheart": "909038004",
    "rampagebook": "909034001",
    "guildflag": "909049017",
    "fish": "909040004",
    "inosuke": "909041003",
    "shootdance": "909000008",
    "flowrs": "909000010",
    "mummydance": "909000011",
    "shuffling": "909000013",
    "dragonfist": "909000015",
    "dangerousgame": "909000016",
    "jaguardance": "909000017",
    "threaten": "909000018",
    "shakewithme": "909000019",
    "devilsmove": "909000020",
    "furiousslam": "909000021",
    "moonflip": "909000022",
    "wigglewalk": "909000023",
    "battledance": "909000024",
    "shakeitup": "909000026",
    "gloriousspin": "909000027",
    "cranekick": "909000028",
    "partydance": "909000029",
    "jigdance": "909000031",
    "soulshaking": "909000033",
    "healingdance": "909000035",
    "topdj": "909000036",
    "deathglare": "909000037",
    "powerofmoney": "909000038",
    "eatmydust": "909000039",
    "bonappetit": "909000042",
    "aimfire": "909000043",
    "swan": "909000044",
    "teatime": "909000046",
    "bringiton": "909000047",
    "whyohwhy": "909000048",
    "fancyhands": "909000049",
    "shimmy": "909000051",
    "doggie": "909000052",
    "challengeon": "909000053",
    "lasso": "909000054",
    "imrich": "909000055",
    "morepractice": "909000079",
    "ffws2021": "909000080",
    "dracossoul": "909000081",
    "goodgame": "909000082",
    "greetings": "909000083",
    "walker": "909000084",
    "bornoflight": "909000085",
    "mythosfour": "909000086",
    "championgrab": "909000087",
    "winandchill": "909000088",
    "hadouken": "909000089",
    "bloodwraith": "909000090",
    "bigsmash": "909000091",
    "fancysteps": "909000092",
    "allincontrol": "909000093",
    "debugging": "909000094",
    "waggorwave": "909000095",
    "crazyguitar": "909000096",
    "poof": "909000097",
    "chosenvictor": "909000098",
    "challenger": "909000099",
    "partygame5": "909000100",
    "partygame6": "909000101",
    "partygame3": "909000102",
    "partygame4": "909000103",
    "partygame7": "909000104",
    "partygame1": "909000105",
    "partygame8": "909000106",
    "partygame2": "909000107",
    "dribbleking": "909000121",
    "ffwsguitar": "909000122",
    "mindit": "909000123",
    "goldencombo": "909000124",
    "sickmoves": "909000125",
    "rapswag": "909000126",
    "battleinstyle": "909000127",
    "rulersflag": "909000128",
    "moneythrow": "909000129",
    "endlessbullets": "909000130",
    "smoothsway": "909000131",
    "number1": "909000132",
    "fireslam": "909000133",
    "heartbroken": "909000134",
    "rockpaperscissors": "909000135",
    "shatteredreality": "909000136",
    "haloofmusic": "909000137",
    "burntbbq": "909000138",
    "switchingsteps": "909000139",
    "creedslay": "909000140",
    "leapoffail": "909000141",
    "rhythmgirl": "909000142",
    "helicoptership": "909000143",
    "kungfutigers": "909000144",
    "possessedwarrior": "909000145",
    "raiseyourthumb": "909000150",

    "fireborn": "909033001",
    "goldenfeather": "909033002",
    "comeanddance": "909033003",
    "dropkick": "909033004",
    "sitdown": "909033005",
    "booyahsparks": "909033006",
    "ffwsdance": "909033007",
    "easypeasy": "909033008",
    "winnerthrow": "909033009",
    "weightofvictory": "909033010",

    "chronicle": "909034001",
    "collapse": "909034002",
    "flaminggroove": "909034003",
    "energetic": "909034004",
    "ridicule": "909034005",
    "teasewaggor": "909034006",
    "greatconductor": "909034007",
    "fakedeath": "909034008",
    "twerk": "909034009",
    "brheroic": "909034010",
    "brmaster": "909034011",
    "csheroic": "909034012",
    "csmaster": "909034013",
    "yesido": "909034014",

    "freemoney": "909035001",
    "singersb03": "909035002",
    "singersb0203": "909035003",
    "singersb010203": "909035004",
    "victoriouseagle": "909035005",
    "flyingsaucer": "909035006",
    "weaponmagician": "909035007",
    "bobbledance": "909035008",
    "weighttraining": "909035009",
    "beautifullove": "909035010",
    "groovemoves": "909035011",
    "howlersrage": "909035012",
    "louderplease": "909035013",
    "ninjastand": "909035014",
    "creatorinaction": "909035015",

    "ghostfloat": "909036001",
    "shibasurf": "909036002",
    "waiterwalk": "909036003",
    "grafficameraman": "909036004",
    "agileboxer": "909036005",
    "sunbathing": "909036006",
    "skateboardswag": "909036008",
    "phantomtamer": "909036009",
    "signal": "909036010",
    "eternaldescent": "909036011",
    "swaggydance": "909036012",
    "admire": "909036014",

    "reindeerfloat": "909037001",
    "bamboodance": "909037002",
    "constellationdance": "909037003",
    "trophygrab": "909037004",
    "starryhands": "909037005",
    "yum": "909037006",
    "happydancing": "909037007",
    "juggle": "909037008",
    "neonsign": "909037009",
    "beasttease": "909037010",
    "drachentear": "909037011",
    "clapdance": "909037012",

    "influencer": "909038001",
    "macarena": "909038002",
    "technoblast": "909038003",
    "valentine": "909038004",
    "angrywalk": "909038005",
    "makesomenoise": "909038006",
    "crocohooray": "909038008",
    "scorpionspin": "909038009",
    "cindersummon": "909038010",
    "shallwedance": "909038011",
    "spinmaster": "909038013",

    "festival": "909039001",
    "artisticdance": "909039002",
    "forwardbackward": "909039003",
    "scorpionfriend": "909039004",
    "achingpower": "909039005",
    "earthlyforce": "909039006",
    "grenademagic": "909039007",
    "ohyeah": "909039008",
    "graceonwheels": "909039009",
    "flex": "909039010",
    "firebeasttamer": "909039012",
    "crimsontunes": "909039013",
    "swaggyvsteps": "909039014",

    "chromaticfinish": "909040001",
    "smashthefeather": "909040002",
    "sonoroussteps": "909040003",
    "chromaticpop": "909040005",
    "chromatwist": "909040006",
    "birthofjustice": "909040008",
    "spidersense": "909040009",
    "chromasonicshot": "909040010",
    "playwiththunderbolt": "909040011",
    "anniversary": "909040012",
    "wisdomswing": "909040013",

    "thunderflash": "909041001",
    "whirlpool": "909041002",
    "flyinginksword": "909041004",
    "dancepuppet": "909041006",
    "highknees": "909041007",
    "feeltheelectricity": "909041009",
    "whacacotton": "909041010",
    "honorablemention": "909041011",
    "brgrandmaster": "909041012",
    "monsterclubbing": "909041014",
    "basudaradance": "909041015",

    "stirfryfrostfire": "909042001",
    "moneyrain": "909042002",
    "frostfirecalling": "909042003",
    "stompingfoot": "909042004",
    "thisway": "909042005",
    "excellentservice": "909042006",
    "realtiger": "909042008",
    "celebrationschuss": "909042009",
    "dawnvoyage": "909042011",
    "lamborghiniride": "909042012",
    "toiletman": "909042013",
    "handgrooves": "909042016",
    "kemusan": "909042018",

    "ribbitrider": "909043001",
    "innerself": "909043002",
    "emperortreasure": "909043003",
    "whysochaos": "909043004",
    "hugefeast": "909043005",
    "colorburst": "909043006",
    "dragonswipe": "909043007",
    "samba": "909043008",
    "speedsummon": "909043009",
    "whatamatch": "909043010",
    "whatapair": "909043013",

    "bytemounting": "909044001",
    "unicyclist": "909044002",
    "basketrafting": "909044003",
    "happylamb": "909044004",
    "paradox": "909044005",
    "harmoniousparadox": "909044006",
    "raiseyourthumb2": "909044007",
    "claphands": "909044008",
    "donedeal": "909044009",
    "starcatcher": "909044010",
    "paradoxwings": "909044011",
    "zombified": "909044012",
    "honkup": "909044016",

    "cyclone": "909045001",
    "springrocker": "909045002",
    "giddyup": "909045003",
    "goosydance": "909045004"
    }                                       
                                      
                        emote_id = e_emotes.get(e_choice)
                        
                        
                        if not emote_id:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Invalid choice: {e_choice}. Please use a number from 1-417.", uid_sender))
                            continue
                        
                        

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Activating emote {emote_id} for {len(target_ids)} player(s)...", uid_sender))

                        for target_id in target_ids:
                            
                            emote_packet = self.send_emote(target_id, emote_id)
                            socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.1) # Small delay between packets
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote command finished!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing @a command: {e}")
                        try:
                            emote_packet = self.send_emote(target_id, emote_id)
                            socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.1) # Small delay between packets
                        except:
                            pass             
                
                
                if "1200" in data.hex()[0:4] and b'@es' in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Command format: @b <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'@es')[1].split(b'(')[0].decode().strip().split()
                        if len(command_parts) < 1:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /es <target_id> <emote_id>", uid_sender))
                            continue

                        e_choice = command_parts[-1]
                        target_ids = [uid_sender]
                        
                        e_emotes = {
    "1":   "909000001",
    "lol":   "909000002",
    "3":   "909000003",
    "4":   "909000004",
    "5":   "909000005",
    "6":   "909000006",
    "7":   "909000007",
    "8":   "909000008",
    "9":   "909000009",
    "10":  "909000010",
    "11":  "909000011",
    "12":  "909000012",
    "13":  "909000013",
    "14":  "909000014",
    "15":  "909000015",
    "16":  "909000016",
    "17":  "909000017",
    "18":  "909000018",
    "19":  "909000019",
    "20":  "909000020",
    "21":  "909000021",
    "22":  "909000022",
    "23":  "909000023",
    "24":  "909000024",
    "25":  "909000025",
    "26":  "909000026",
    "27":  "909000027",
    "28":  "909000028",
    "29":  "909000029",
    "30":  "909000031",
    "31":  "909000032",
    "32":  "909000033",
    "33":  "909000034",
    "34":  "909000035",
    "35":  "909000036",
    "36":  "909000037",
    "37":  "909000038",
    "38":  "909000039",
    "39":  "909000040",
    "40":  "909000041",
    "41":  "909000042",
    "42":  "909000043",
    "43":  "909000044",
    "44":  "909000045",
    "45":  "909000046",
    "46":  "909000047",
    "47":  "909000048",
    "48":  "909000049",
    "49":  "909000051",
    "50":  "909000052",
    "51":  "909000053",
    "52":  "909000054",
    "53":  "909000055",
    "54":  "909000056",
    "55":  "909000057",
    "56":  "909000058",
    "57":  "909000059",
    "58":  "909000060",
    "59":  "909000061",
    "60":  "909000062",
    "61":  "909000063",
    "62":  "909000064",
    "63":  "909000065",
    "64":  "909000066",
    "65":  "909000067",
    "66":  "909000068",
    "67":  "909000069",
    "68":  "909000070",
    "69":  "909000071",
    "70":  "909000072",
    "71":  "909000073",
    "72":  "909000074",
    "73":  "909000075",
    "74":  "909000076",
    "75":  "909000077",
    "76":  "909000078",
    "77":  "909000079",
    "78":  "909000080",
    "79":  "909000081",
    "80":  "909000082",
    "81":  "909000083",
    "82":  "909000084",
    "83":  "909000085",
    "84":  "909000086",
    "85":  "909000087",
    "86":  "909000088",
    "87":  "909000089",
    "88":  "909000090",
    "89":  "909000091",
    "90":  "909000092",
    "91":  "909000093",
    "92":  "909000094",
    "93":  "909000095",
    "94":  "909000096",
    "95":  "909000097",

    "106": "909000108",
    "119": "909000121",
    "120": "909000122",
    "121": "909000123",
    "122": "909000124",
    "123": "909000125",
    "124": "909000126",
    "125": "909000127",
    "126": "909000128",
    "127": "909000129",
    "128": "909000130",
    "129": "909000131",
    "130": "909000132",
    "131": "909000133",
    "132": "909000134",
    "133": "909000135",
    "134": "909000136",
    "135": "909000137",
    "136": "909000138",
    "137": "909000139",
    "138": "909000140",
    "139": "909000141",
    "140": "909000142",

    "142": "909000144",
    "143": "909000145",
    "144": "909000150",

    "145": "909033001",
    "146": "909033002",
    "147": "909033003",
    "148": "909033004",
    "149": "909033005",
    "150": "909033006",
    "151": "909033007",
    "152": "909033008",
    "153": "909033009",
    "154": "909033010",

    "155": "909034001",
    "156": "909034002",
    "157": "909034003",
    "158": "909034004",
    "159": "909034005",
    "160": "909034006",
    "161": "909034007",
    "162": "909034008",
    "163": "909034009",
    "164": "909034010",
    "165": "909034011",
    "166": "909034012",
    "167": "909034013",
    "168": "909034014",

    "169": "909035001",

    "173": "909035005",
    "174": "909035006",
    "175": "909035007",
    "176": "909035008",
    "177": "909035009",
    "178": "909035010",
    "179": "909035011",
    "180": "909035012",
    "181": "909035013",
    "182": "909035014",
    "183": "909035015",

    "184": "909036001",
    "185": "909036002",
    "186": "909036003",
    "187": "909036004",
    "188": "909036005",
    "189": "909036006",
    "190": "909036008",
    "191": "909036009",
    "192": "909036010",
    "193": "909036011",
    "194": "909036012",
    "195": "909036014",

    "196": "909037001",
    "197": "909037002",
    "198": "909037003",
    "199": "909037004",
    "200": "909037005",
    "201": "909037006",
    "202": "909037007",
    "203": "909037008",
    "204": "909037009",
    "205": "909037010",
    "206": "909037011",
    "207": "909037012",

    "208": "909038001",
    "210": "909038003",
    "211": "909038004",
    "212": "909038005",
    "213": "909038006",
    "214": "909038008",
    "215": "909038009",
    "216": "909038010",
    "217": "909038011",
    "218": "909038012",
    "219": "909038013",

    "220": "909039001",
    "221": "909039002",
    "222": "909039003",
    "223": "909039004",
    "224": "909039005",
    "225": "909039006",
    "226": "909039007",
    "227": "909039008",
    "228": "909039009",
    "229": "909039010",
    "230": "909039011",
    "231": "909039012",
    "232": "909039013",
    "233": "909039014",

    "234": "909040001",
    "235": "909040002",
    "236": "909040003",
    "237": "909040004",
    "238": "909040005",
    "239": "909040006",
    "240": "909040008",
    "241": "909040009",
    "242": "909040010",
    "243": "909040011",
    "244": "909040012",
    "245": "909040013",

    "247": "909041001",
    "248": "909041002",
    "249": "909041003",
    "250": "909041004",
    "251": "909041005",
    "252": "909041006",
    "253": "909041007",
    "254": "909041008",
    "255": "909041009",
    "256": "909041010",
    "257": "909041011",
    "258": "909041012",
    "259": "909041013",
    "260": "909041014",
    "261": "909041015",

    "262": "909042001",
    "263": "909042002",
    "264": "909042003",
    "265": "909042004",
    "266": "909042005",
    "267": "909042006",
    "lvl100": "909042007",
    "100lvl": "909042007",
    "100": "909042007",
    "269": "909042008",
    "270": "909042009",
    "271": "909042011",
    "272": "909042012",
    "274": "909042016",
    "275": "909042017",
    "276": "909042018",

    "277": "909043001",
    "278": "909043002",
    "279": "909043003",
    "280": "909043004",
    "281": "909043005",
    "282": "909043006",
    "283": "909043007",
    "284": "909043008",
    "285": "909043009",

    "288": "909044001",
    "289": "909044002",
    "290": "909044003",
    "291": "909044004",
    "292": "909044005",
    "294": "909044007",
    "295": "909044008",
    "296": "909044009",
    "297": "909044010",
    "298": "909044011",
    "299": "909044012",
    "300": "909044015",
    "301": "909044016",

    "302": "909045001",
    "303": "909045002",
    "304": "909045003",
    "305": "909045004",
    "306": "909045005",
    "307": "909045006",
    "308": "909045007",
    "309": "909045008",
    "310": "909045009",
    "311": "909045010",
    "312": "909045011",
    "314": "909045015",
    "315": "909045016",
    
    "316": "909045017",
    "317": "909046001",
    "318": "909046002",
    "319": "909046003",
    "322": "909046006",
    "323": "909046007",
    "324": "909046008",
    "325": "909046009",
    "326": "909046010",
    "327": "909046011",
    "328": "909046012",
    "329": "909046013",
    "330": "909046014",
    "331": "909046015",
    "332": "909046016",
    "333": "909046017",
    "334": "909047001",
    "337": "909047004",
    "338": "909047005",
    "339": "909047006",
    "340": "909047007",
    "341": "909047008",
    "342": "909047009",
    "343": "909047010",
    "344": "909047011",
    "345": "909047012",
    "346": "909047013",
    "347": "909047015",
    "348": "909047016",
    "349": "909047017",
    "350": "909047018",
    "351": "909047019",
    "353": "909048002",
    "354": "909048003",
    "355": "909048004",
    "356": "909048005",
    "357": "909048006",
    "358": "909048007",
    "359": "909048008",
    "361": "909048010",
    "362": "909048011",
    "363": "909048012",
    "364": "909048013",
    "365": "909048014",
    "366": "909048015",
    "367": "909048016",
    "368": "909048017",
    "369": "909048018",
    "370": "909049001",
    "371": "909049002",
    "372": "909049003",
    "373": "909049004",
    "374": "909049005",
    "375": "909049006",
    "376": "909049007",
    "378": "909049009",
    "379": "909049010",
    "380": "909049011",
    "381": "909049012",
    "382": "909049013",
    "383": "909049014",
    "384": "909049015",
    "385": "909049016",
    "386": "909049017",
    "387": "909049018",
    "388": "909049019",
    "389": "909049020",
    "390": "909049021",
    "391": "909050002",
    "393": "909050004",
    "394": "909050005",
    "395": "909050006",
    "396": "909050008",
    "ring": "909050009",
    "398": "909050010",
    "399": "909050011",
    "400": "909050012",
    "401": "909050013",
    "402": "909050014",
    "403": "909050015",
    "404": "909050016",
    "405": "909050017",
    "406": "909050018",
    "407": "909050019",
    "408": "909050020",
    "409": "909050021",

    "410": "909046004",
    "411": "909046005",
    "412": "909047002",
    "413": "909047003",
    "414": "909048001",
    "415": "909048009",
    "416": "909049008",
    "417": "909050003"
}
                        


                        emote_id = e_emotes.get(e_choice)                                               

                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]ATTACKING with emote {emote_id} on {len(target_ids)} player(s)!", uid_sender))

                        # Loop for repeating the emote quickly
                        emote_keys = list(range(1, 401))  # Assuming emotes numbered 1 to 400
                        e = 0  # start index
                        repetitions = 200

                        while e < len(emote_keys) and repetitions > 0:
                            emote_key = str(emote_keys[e])
                            emote_id = e_emotes.get(emote_key)
                            if not emote_id:
                                e += 3
                                continue

                            for target_id in target_ids:
                                if e>=0:
                                    emote_packet = self.send_emote(target_id, emote_id)
                                    socket_client.send(emote_packet)
                            time.sleep(0.08)  # Small delay between sends
                            time.sleep(5)     # Wait 5 seconds before next emote

                            e += 1
                            repetitions -= 1

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote attack finished!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing /es command: {e}")
                        try:                   
                             # Loop for repeating the emote quickly
                            emote_keys = list(range(1, 401))  # Assuming emotes numbered 1 to 400
                            e = 0  # start index
                            repetitions = 200

                            while e < len(emote_keys) and repetitions > 0:
                                emote_key = str(emote_keys[e])
                                emote_id = e_emotes.get(emote_key)
                                if not emote_id:
                                    e += 3
                                    continue
                                
                                if e >=0:    
                                    emote_packet = self.send_emote(target_id, emote_id)
                                    socket_client.send(emote_packet)
                                time.sleep(0.08)  # Small delay between sends
                                time.sleep(5)     # Wait 5 seconds before next emote

                                e += 1
                                repetitions -= 1

                            clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote attack finished!", uid_sender))

                        except:
                            pass                
                            
                            
                            
                
                if "1200" in data.hex()[0:4] and b'/es' in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Command format: @b <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'/es')[1].split(b'(')[0].decode().strip().split()
                        if len(command_parts) < 2:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /es <target_id> <emote_id>", uid_sender))
                            continue

                        e_choice = command_parts[-1]
                        target_ids = command_parts[:-1]
                        
                        e_emotes = {
    "1":   "909000001",
    "lol":   "909000002",
    "3":   "909000003",
    "4":   "909000004",
    "5":   "909000005",
    "6":   "909000006",
    "7":   "909000007",
    "8":   "909000008",
    "9":   "909000009",
    "10":  "909000010",
    "11":  "909000011",
    "12":  "909000012",
    "13":  "909000013",
    "14":  "909000014",
    "15":  "909000015",
    "16":  "909000016",
    "17":  "909000017",
    "18":  "909000018",
    "19":  "909000019",
    "20":  "909000020",
    "21":  "909000021",
    "22":  "909000022",
    "23":  "909000023",
    "24":  "909000024",
    "25":  "909000025",
    "26":  "909000026",
    "27":  "909000027",
    "28":  "909000028",
    "29":  "909000029",
    "30":  "909000031",
    "31":  "909000032",
    "32":  "909000033",
    "33":  "909000034",
    "34":  "909000035",
    "35":  "909000036",
    "36":  "909000037",
    "37":  "909000038",
    "38":  "909000039",
    "39":  "909000040",
    "40":  "909000041",
    "41":  "909000042",
    "42":  "909000043",
    "43":  "909000044",
    "44":  "909000045",
    "45":  "909000046",
    "46":  "909000047",
    "47":  "909000048",
    "48":  "909000049",
    "49":  "909000051",
    "50":  "909000052",
    "51":  "909000053",
    "52":  "909000054",
    "53":  "909000055",
    "54":  "909000056",
    "55":  "909000057",
    "56":  "909000058",
    "57":  "909000059",
    "58":  "909000060",
    "59":  "909000061",
    "60":  "909000062",
    "61":  "909000063",
    "62":  "909000064",
    "63":  "909000065",
    "64":  "909000066",
    "65":  "909000067",
    "66":  "909000068",
    "67":  "909000069",
    "68":  "909000070",
    "69":  "909000071",
    "70":  "909000072",
    "71":  "909000073",
    "72":  "909000074",
    "73":  "909000075",
    "74":  "909000076",
    "75":  "909000077",
    "76":  "909000078",
    "77":  "909000079",
    "78":  "909000080",
    "79":  "909000081",
    "80":  "909000082",
    "81":  "909000083",
    "82":  "909000084",
    "83":  "909000085",
    "84":  "909000086",
    "85":  "909000087",
    "86":  "909000088",
    "87":  "909000089",
    "88":  "909000090",
    "89":  "909000091",
    "90":  "909000092",
    "91":  "909000093",
    "92":  "909000094",
    "93":  "909000095",
    "94":  "909000096",
    "95":  "909000097",

    "106": "909000108",
    "119": "909000121",
    "120": "909000122",
    "121": "909000123",
    "122": "909000124",
    "123": "909000125",
    "124": "909000126",
    "125": "909000127",
    "126": "909000128",
    "127": "909000129",
    "128": "909000130",
    "129": "909000131",
    "130": "909000132",
    "131": "909000133",
    "132": "909000134",
    "133": "909000135",
    "134": "909000136",
    "135": "909000137",
    "136": "909000138",
    "137": "909000139",
    "138": "909000140",
    "139": "909000141",
    "140": "909000142",

    "142": "909000144",
    "143": "909000145",
    "144": "909000150",

    "145": "909033001",
    "146": "909033002",
    "147": "909033003",
    "148": "909033004",
    "149": "909033005",
    "150": "909033006",
    "151": "909033007",
    "152": "909033008",
    "153": "909033009",
    "154": "909033010",

    "155": "909034001",
    "156": "909034002",
    "157": "909034003",
    "158": "909034004",
    "159": "909034005",
    "160": "909034006",
    "161": "909034007",
    "162": "909034008",
    "163": "909034009",
    "164": "909034010",
    "165": "909034011",
    "166": "909034012",
    "167": "909034013",
    "168": "909034014",

    "169": "909035001",

    "173": "909035005",
    "174": "909035006",
    "175": "909035007",
    "176": "909035008",
    "177": "909035009",
    "178": "909035010",
    "179": "909035011",
    "180": "909035012",
    "181": "909035013",
    "182": "909035014",
    "183": "909035015",

    "184": "909036001",
    "185": "909036002",
    "186": "909036003",
    "187": "909036004",
    "188": "909036005",
    "189": "909036006",
    "190": "909036008",
    "191": "909036009",
    "192": "909036010",
    "193": "909036011",
    "194": "909036012",
    "195": "909036014",

    "196": "909037001",
    "197": "909037002",
    "198": "909037003",
    "199": "909037004",
    "200": "909037005",
    "201": "909037006",
    "202": "909037007",
    "203": "909037008",
    "204": "909037009",
    "205": "909037010",
    "206": "909037011",
    "207": "909037012",

    "208": "909038001",
    "210": "909038003",
    "211": "909038004",
    "212": "909038005",
    "213": "909038006",
    "214": "909038008",
    "215": "909038009",
    "216": "909038010",
    "217": "909038011",
    "218": "909038012",
    "219": "909038013",

    "220": "909039001",
    "221": "909039002",
    "222": "909039003",
    "223": "909039004",
    "224": "909039005",
    "225": "909039006",
    "226": "909039007",
    "227": "909039008",
    "228": "909039009",
    "229": "909039010",
    "230": "909039011",
    "231": "909039012",
    "232": "909039013",
    "233": "909039014",

    "234": "909040001",
    "235": "909040002",
    "236": "909040003",
    "237": "909040004",
    "238": "909040005",
    "239": "909040006",
    "240": "909040008",
    "241": "909040009",
    "242": "909040010",
    "243": "909040011",
    "244": "909040012",
    "245": "909040013",

    "247": "909041001",
    "248": "909041002",
    "249": "909041003",
    "250": "909041004",
    "251": "909041005",
    "252": "909041006",
    "253": "909041007",
    "254": "909041008",
    "255": "909041009",
    "256": "909041010",
    "257": "909041011",
    "258": "909041012",
    "259": "909041013",
    "260": "909041014",
    "261": "909041015",

    "262": "909042001",
    "263": "909042002",
    "264": "909042003",
    "265": "909042004",
    "266": "909042005",
    "267": "909042006",
    "lvl100": "909042007",
    "100lvl": "909042007",
    "100": "909042007",
    "269": "909042008",
    "270": "909042009",
    "271": "909042011",
    "272": "909042012",
    "274": "909042016",
    "275": "909042017",
    "276": "909042018",

    "277": "909043001",
    "278": "909043002",
    "279": "909043003",
    "280": "909043004",
    "281": "909043005",
    "282": "909043006",
    "283": "909043007",
    "284": "909043008",
    "285": "909043009",

    "288": "909044001",
    "289": "909044002",
    "290": "909044003",
    "291": "909044004",
    "292": "909044005",
    "294": "909044007",
    "295": "909044008",
    "296": "909044009",
    "297": "909044010",
    "298": "909044011",
    "299": "909044012",
    "300": "909044015",
    "301": "909044016",

    "302": "909045001",
    "303": "909045002",
    "304": "909045003",
    "305": "909045004",
    "306": "909045005",
    "307": "909045006",
    "308": "909045007",
    "309": "909045008",
    "310": "909045009",
    "311": "909045010",
    "312": "909045011",
    "314": "909045015",
    "315": "909045016",
    
    "316": "909045017",
    "317": "909046001",
    "318": "909046002",
    "319": "909046003",
    "322": "909046006",
    "323": "909046007",
    "324": "909046008",
    "325": "909046009",
    "326": "909046010",
    "327": "909046011",
    "328": "909046012",
    "329": "909046013",
    "330": "909046014",
    "331": "909046015",
    "332": "909046016",
    "333": "909046017",
    "334": "909047001",
    "337": "909047004",
    "338": "909047005",
    "339": "909047006",
    "340": "909047007",
    "341": "909047008",
    "342": "909047009",
    "343": "909047010",
    "344": "909047011",
    "345": "909047012",
    "346": "909047013",
    "347": "909047015",
    "348": "909047016",
    "349": "909047017",
    "350": "909047018",
    "351": "909047019",
    "353": "909048002",
    "354": "909048003",
    "355": "909048004",
    "356": "909048005",
    "357": "909048006",
    "358": "909048007",
    "359": "909048008",
    "361": "909048010",
    "362": "909048011",
    "363": "909048012",
    "364": "909048013",
    "365": "909048014",
    "366": "909048015",
    "367": "909048016",
    "368": "909048017",
    "369": "909048018",
    "370": "909049001",
    "371": "909049002",
    "372": "909049003",
    "373": "909049004",
    "374": "909049005",
    "375": "909049006",
    "376": "909049007",
    "378": "909049009",
    "379": "909049010",
    "380": "909049011",
    "381": "909049012",
    "382": "909049013",
    "383": "909049014",
    "384": "909049015",
    "385": "909049016",
    "386": "909049017",
    "387": "909049018",
    "388": "909049019",
    "389": "909049020",
    "390": "909049021",
    "391": "909050002",
    "393": "909050004",
    "394": "909050005",
    "395": "909050006",
    "396": "909050008",
    "ring": "909050009",
    "398": "909050010",
    "399": "909050011",
    "400": "909050012",
    "401": "909050013",
    "402": "909050014",
    "403": "909050015",
    "404": "909050016",
    "405": "909050017",
    "406": "909050018",
    "407": "909050019",
    "408": "909050020",
    "409": "909050021",

    "410": "909046004",
    "411": "909046005",
    "412": "909047002",
    "413": "909047003",
    "414": "909048001",
    "415": "909048009",
    "416": "909049008",
    "417": "909050003"
}
                        


                        emote_id = e_emotes.get(e_choice)                                               

                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]ATTACKING with emote {emote_id} on {len(target_ids)} player(s)!", uid_sender))

                        # Loop for repeating the emote quickly
                        for _ in range(200): # Repeats 200 times
                            for target_id in target_ids:
                                if target_id.isdigit() and emote_id.isdigit():
                                    emote_packet = self.send_emote(target_id, emote_id)
                                    socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.08) # Fast repeat speed

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote attack finished!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing /es command: {e}")
                        try:
                            uid_sender = json.loads(get_available_room(data.hex()[10:]))["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error processing /es command.", uid_sender))
                        except:
                            pass                
                                            
                

                            
                            
                            
                if "1200" in data.hex()[0:4] and b"/evo" in data:
                    try:
                        # Step 1: Get the sender's UID for replies
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Step 2: Parse the command parts safely
                        command_parts = data.split(b'/evo')[1].split(b'(')[0].decode().strip().split()

                        # Step 3: Validate the number of arguments
                        if len(command_parts) < 2:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /evo <player_id> <number>", uid_sender))
                            continue
                        
                        # Step 4: Assign arguments robustly
                        # The last item is the emote choice, the first is the target ID.
                        evo_choice = command_parts[-1] 
                        target_id = command_parts[0]

                        # Step 5: Define the mapping of choices to emote IDs
                        evo_emotes = {
                            "1": "909000063",   # AK
                            "2": "909000068",   # SCAR
                            "3": "909000075",   # 1st MP40
                            "4": "909040010",   # 2nd MP40
                            "5": "909000081",   # 1st M1014
                            "6": "909039011",   # 2nd M1014
                            "7": "909000085",   # XM8
                            "8": "909000090",   # Famas
                            "9": "909000098",   # UMP
                            "10": "909035007",  # M1887
                            "11": "909042008",  # Woodpecker
                            "12": "909041005",  # Groza
                            "13": "909033001",  # M4A1
                            "14": "909038010",  # Thompson
                            "15": "909038012",  # G18
                            "16": "909045001",  # Parafal
                            "17": "909049010",   # P90
                            "18": "909051003"   #m60
                        }
                        emote_id = evo_emotes.get(evo_choice)

                        # Step 6: Validate the chosen number. If it's not in the dictionary, emote_id will be None.
                        if not emote_id:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Invalid choice: {evo_choice}. Please use a number from 1-18.", uid_sender))
                            continue

                        # Step 7: Validate IDs and send the action packet
                        if target_id.isdigit() and emote_id.isdigit():
                            # Create the game action packet
                            emote_packet = self.send_emote(target_id, emote_id)
                            # Send the action to the game server
                            socket_client.send(emote_packet)
                            time.sleep(0.1)
                            
                            # Send a chat confirmation back to the user
                            clients.send(self.GenResponsMsg(f"[C][B][00FF00]EVO emote #{evo_choice} sent to {target_id}!", uid_sender))
                        else:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Invalid Player ID provided.", uid_sender))

                    except Exception as e:
                        # Consistent error handling with restart
                        logging.error(f"Error processing /evo command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()
                        
                        
                        
                if "1200" in data.hex()[0:4] and b"@evos" in data:
                    try:
                        # Step 1: Get the sender's UID for replies
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Step 2: Parse the command parts safely
                        command_parts = data.split(b'@evos')[1].split(b'(')[0].decode().strip().split()

                        # Step 3: Validate the number of arguments
                        if len(command_parts) < 0:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /evo <player_id> <number>", uid_sender))
                            continue
                        
                        # Step 4: Assign arguments robustly
                        # The last item is the emote choice, the first is the target ID.
                        evo_choice = 1
                        target_id = [uid_sender]
                        target_ids = target_id

                        # Step 5: Define the mapping of choices to emote IDs
                        evo_emotes = {
                            "1": "909000063",   # AK
                            "2": "909000068",   # SCAR
                            "3": "909000075",   # 1st MP40
                            "4": "909040010",   # 2nd MP40
                            "5": "909000081",   # 1st M1014
                            "6": "909039011",   # 2nd M1014
                            "7": "909000085",   # XM8
                            "8": "909000090",   # Famas
                            "9": "909000098",   # UMP
                            "10": "909035007",  # M1887
                            "11": "909042008",  # Woodpecker
                            "12": "909041005",  # Groza
                            "13": "909033001",  # M4A1
                            "14": "909038010",  # Thompson
                            "15": "909038012",  # G18
                            "16": "909045001",  # Parafal
                            "17": "909049010",   # P90
                            "18": "909051003"   #m60
                        }
                        emote_id = evo_emotes.get(evo_choice)
                        
                        
                        # Step 7: Validate IDs and send the action packet
                        emote_keys = list(range(1, 19))  # Assuming emotes numbered 1 to 400
                        e = 0  # start index
                        
                        reapets = 19

                        while e< len(emote_keys) and reapets > 1:
                            emote_key = str(emote_keys[e])
                            emote_id = evo_emotes.get(emote_key)
                            if not emote_id:
                                evo += 1
                                continue

                            for target_id in target_ids:
                                if reapets >=1:
                                    emote_packet = self.send_emote(target_id, emote_id)
                                    socket_client.send(emote_packet)
                                time.sleep(0.08)  # Small delay between sends
                                time.sleep(5)     # Wait 5 seconds before next emote

                                e += 1
                                reapets -= 1
                                                   
                       
                                if reapets == 0:
                                    restart_program()
                        # Step 6: Validate the chosen number. If it's not in the dictionary, emote_id will be None.

                            
                            # Send a chat confirmation back to the user
                                    clients.send(self.GenResponsMsg(f"[C][B][00FF00]EVO emote #{evo_choice} sent to {target_id}!", uid_sender))
                        else:
                            clients.send(self.GenResponsMsg("[C][B][00FF00]@evos Command Successful.", uid_sender))
                            restart_program()

                    except Exception as e:
                        # Consistent error handling with restart
                        logging.error(f"Error processing /evo command: {e}. Restarting.")
                        try:

                            if reapets == 0:
                              
                                clients.send(self.GenResponsMsg("[C][B][FF0000] completd.", uid_sender))
                                
                                restart_program()
                                                   
                        except:
                            pass 
                        restart_program()
                        
                        
                        
                        
                if "1200" in data.hex()[0:4] and b"/TCP" in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        client_id = parsed_data["5"]["data"]["1"]["data"]

                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][1E90FF]Started Reject Spam on: {fix_num(client_id)}",
                                client_id
                            )
                        )

                        for _ in range(150):
                            socket_client.send(self.boss1(client_id))
                            socket_client.send(self.boss1(client_id))
                            time.sleep(0.2)

                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][00FF00]✅ Reject Spam Completed Successfully for ID {fix_num(client_id)}",
                                client_id
                            )
                        )

                    except Exception as e:
                        logging.error(f"[WHISPER] Error in /xr command: {e}")
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][FF0000]❌ Error: {e}",
                                client_id
                            )
                        )
                         
                
                
                
                if "1200" in data.hex()[0:4] and b"/start" in data:
                    try:
                        split_data = re.split(rb'/start', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a team code.", uid))
                            continue

                        team_code = command_parts[0]
                        spam_count = 20
                        if len(command_parts) > 1 and command_parts[1].isdigit():
                            spam_count = int(command_parts[1])
                        if spam_count > 50:
                            spam_count = 50

                        clients.send(
                            self.GenResponsMsg(f"[C][B][FFA500]Joining lobby to force start...", uid)
                        )
                        join_teamcode(socket_client, team_code, key, iv)
                        time.sleep(2)
                        clients.send(
                            self.GenResponsMsg(f"[C][B][FF0000]Spamming start command {spam_count} times!", uid)
                        )
                        start_packet = self.start_autooo()
                        for _ in range(spam_count):
                            socket_client.send(start_packet)
                            time.sleep(0.2)
                        leave_packet = self.leave_s()
                        socket_client.send(leave_packet)
                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Force start process finished.", uid)
                        )
                    except Exception as e:
                        logging.error(f"An error occurred in /start command: {e}. Restarting.")
                        restart_program()
                if "1200" in data.hex()[0:4] and b"/addVOPN" in data:
                    try:
                        i = re.split("/addVOPN", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/add', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                            numsc1 = room_data[1] if len(room_data) > 1 else None

                            if numsc1 is None:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/add 123[c]456[c]78 4\n/add 123[c]456[c]78 5", uid
                                    )
                                )
                            else:
                                numsc = int(numsc1) - 1
                                if int(numsc1) < 3 or int(numsc1) > 6:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][FF0000] Usage : /add <uid> <Squad Type>\n[ffffff]Example : \n/add 12345678 4\n/add 12345678 5", uid
                                        )
                                    )
                                else:
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(1)
                                    packetfinal = self.changes(int(numsc))
                                    socket_client.send(packetfinal)
                                    
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                                    invitessa = self.invite_skwad(iddd1)
                                    socket_client.send(invitessa)
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][00ff00]- Accept The Invite Quickly ! ", uid
                                        )
                                    )
                                    leaveee1 = True
                                    while leaveee1:
                                        if leaveee == True:
                                            #logging.info("Leave")
                                            leavee = self.leave_s()
                                            sleep(5)
                                            socket_client.send(leavee)   
                                            leaveee = False
                                            leaveee1 = False
                                            clients.send(
                                                self.GenResponsMsg(
                                                    f"[C][B] [FF00FF]success !", uid
                                                )
                                            )    
                                        if pleaseaccept == True:
                                            #logging.info("Leave")
                                            leavee = self.leave_s()
                                            socket_client.send(leavee)   
                                            leaveee1 = False
                                            pleaseaccept = False
                                            clients.send(
                                                self.GenResponsMsg(
                                                    f"[C][B] [FF00FF]Please accept the invite", uid
                                                )
                                            )   
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/inv 123[c]456[c]78 4\n/inv 123[c]456[c]78 5", uid
                                )
                            )
                    except Exception as e:
                        logging.error(f"Error processing /addVOPN command: {e}. Restarting.")
                        restart_program()
            # --- START: Added for error handling ---
            except Exception as e:
                logging.critical(f"A critical unhandled error occurred in the main connect loop: {e}. The bot will restart.")
                restart_program()
            # --- END: Added for error handling ---

	                    
                    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                #logging.info(parsed_data)
                
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            
            except requests.RequestException as e:
                logging.error(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        logging.critical("Failed to get login data after multiple attempts. Restarting.")
        restart_program() # Changed to restart if it fails completely
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
                       'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            #logging.info(key, iv)
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token_data = self.guest_token(self.id, self.password)
        if not token_data:
            logging.critical("Failed to get token data from guest_token. Restarting.")
            restart_program()

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        g_token = token
        #logging.info(f"{whisper_ip}, {whisper_port}")
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            logging.info(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            logging.error(f"Error processing token: {e}. Restarting.")
            restart_program()

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                logging.warning('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            logging.info("Final token constructed successfully.")
        except Exception as e:
            logging.error(f"Error constructing final token: {e}. Restarting.")
            restart_program()
        token = final_token
        self.connect(token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        
      
        return token, key, iv
        
with open('bot.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    logging.info(f"Starting client for ID: {id}")
    client = FF_CLIENT(id, password)
    # The start method is inherited from threading.Thread and calls the run() method
    # The logic is handled within the FF_CLIENT class itself upon instantiation.
    # No need to call client.start() as it's not defined to do anything special here.
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []

# --- START: Modified for robust execution and restart ---
if __name__ == "__main__":
    while True: # This loop ensures the script will always try to restart on a major crash.
        try:
            logging.info("Main execution block started.")
            # Your original threading logic
            for i in range(num_threads):
                ids_for_thread = ids_passwords[i % num_clients]
                id_val, password_val = ids_for_thread
                # The FF_CLIENT init starts the connection logic, which is run in a new thread inside the connect method.
                # The primary thread for each client is created inside its `connect` method.
                # This main thread's purpose is to kick off the clients.
                run_client(id_val, password_val)
                time.sleep(3) # Stagger client startups

            # Keep the main script alive by joining the threads that were created.
            # The threads list is populated inside the connect method.
            logging.info(f"All {len(threads)} client threads initiated. Main thread will now wait.")
            for thread in threads:
                thread.join()

        except KeyboardInterrupt:
            logging.info("Shutdown signal received. Exiting.")
            break
        except Exception as e:
            logging.critical(f"A critical error occurred in the main execution block: {e}")
            logging.info("Restarting the entire application in 5 seconds...")
            time.sleep(5)
            # The restart_program() call will replace this process, so the loop continues in a new instance.
            restart_program()