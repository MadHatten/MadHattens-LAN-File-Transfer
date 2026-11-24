# Read ME
Rename it, re program it,  doesn't matter to me

I care not what someone does with this, just dont be evil with it. If I find you doing evil with this you are no longer invited to my birthday party. 

This is a Two-way file and folder transfer between computers ON THE SAME HOME NETWORK.
Pair a device once with a PIN, tick **Remember this device**, and from then on
transfers go straight through with just a progress bar and always land in the downloads folder. 
Verified to work from Windows to Linux and Linux to Windows


# Preface on Linux 
sometimes you will need to right click on the .py - properties - permisions - check "Allow executing file as program" then double clicking will allow you to select "run in terminal"



 Why the downloads folder? IDK it is just where I wanted to dump them

 Two-way: every computer can send *and* receive
- Send whole folders, with the folder structure (including empty folders) kept intact
- First time from a new device: popup with a PIN and **Allow / Cancel**
- **Remember this device**: after pairing, no PIN and no popup, just the transfer bar
- Every file is checked with SHA-256, so the receiver confirms it arrived bit-perfect
- Never overwrites: duplicates become `file (1).ext` / `Folder (1)`
- Free-space check before accepting anything
- Cancel button on both sides, mid-transfer; partial files are cleaned up
- Dark theme with three tabs: Transfer, Devices, History


# How to Run it

1. Download `MadHattens_lan_filetransfer.py` to each computer.
2. If you do not have PyQt5 installed do it now
   - Windows should automatically download what is needed. Windows doesnt block pip by default # which is one of the reason it sucks imo
   - Ubuntu based (mint, edubuntu etc): `sudo apt install python3-pyqt5`
   - Fedora: `sudo dnf install python3-qt5`
   - CachyOS: `sudo pacman -S python-pyqt5`
3. Run it: `python3 MadHattens_lan_filetransfer.py` (Linux) or `python MadHattens_lan_filetransfer.py` (Windows) you can double click on windows

# if you open it and it opens up the script and not the app see Preface steps above



# Pairing a device (first time only)

1. On the target open the app and leave it running.
2. On your PC, open the app.
3. On your PC, drag a file into the drop area (or click **Add Files** / **Add Folder**).
4. On your PC, type the target's IP in **Send to:** (port number is not required) and click **Send**.
5. On the destination, a popup appears showing a 6-digit **PIN** and **Allow / Cancel**.
6. On the target's popup, tick **Remember this device** if you wish.
7. On your PC, a box appears asking for the PIN. Type the PIN from the server's screen.
8. On your PC, tick **Remember this device**,(if you want to remember) then click **Pair & Send**.
9. On the server popup, click **Allow**.
10. The transfer starts. Both computers now remember each other, in both directions.


# After pairing

1. Make sure the app is open on the other computer.
2. Add your files or folders.
3. Pick the device from the **Send to:** dropdown (remembered devices are listed there), or type its IP.
4. Click **Send**. The transfer bar appears on both sides. No PIN, no popup.


Devices are remembered by a saved ID, not by IP address, so it keeps working if your
router hands out a new IP.

To un-pair a device: **Devices** tab → select it → **Forget Selected**.

# Where things are kept

- Received files: `Downloads/LAN_Transfers` in your home folder
- Settings, remembered devices, history:
  - Windows: `%APPDATA%\MadHattensLANTransfer`
  - Linux: `~/.config/MadHattensLANTransfer`


# Firewall (if a device can't connect)

The app uses TCP port **12345**.

- **Windows:** the first time you run it, Windows will ask you to allow it. click Allow.
- **Ubuntu / Mint / Edubuntu** (only if ufw is turned on):
  `sudo ufw allow 12345/tcp`
- **Fedora:**
  `sudo firewall-cmd --permanent --add-port=12345/tcp`
  then `sudo firewall-cmd --reload`
- **CachyOS:** if it uses ufw: `sudo ufw allow 12345/tcp`.
  If it uses firewalld: same commands as Fedora.
  
  # why is it like that? because im bad at coding and dont do it full time. 
  
  
  
  
  # Advanced options

```
python3 MadHattens_lan_filetransfer.py --port 12345 --download-dir /path/to/folder --config-dir /path/to/settings
```

To send to a device on a different port, type `IP:port` in **Send to:** (e.g. `xxx.xxx.xxx.xxx:12346`).

## Honest limitations

- **Not encrypted.** The PIN and remembered devices stop strangers from *sending* to you, and a
  remembered device has to prove it holds the secret from pairing (copying its ID isn't enough).
  But someone on your home network with packet-sniffing tools could still *watch* a transfer's
  contents. Fine for a home LAN; don't use it over public Wi-Fi.
- **macOS:** should work (PyQt5 runs there) but hasn't been tested. So in theory it should work but I dont own a mac.






