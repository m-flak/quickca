# **quickCA**
#### a GUI for fast certificates- legitimate or otherwise
---

quickCA is a Python GUI application written for the purpose of generating Root Certificate Authorities and processing any CSRs to generate certificates, quickly. *Yes, quickly. No fuss with OpenSSL switches and whatnot... __With quickCA, generate them quickly whether it be legitimate or otherwise__* 

Dependencies
============

quickCA has a few dependencies you'll need to acquire...

 * wxPython
 * certbuilder
 * cryptography
 * oscrypto
 * asn1crypto

*oscrypto & asn1crypto* happen to be dependencies of *certbuilder* that __quickCA__ also uses as well.

You can install all of these dependencies via **pip**:

    pip install -r requirements.txt 

Run this command from the quickCA project directory root. *IF YOU'RE RUNNING DEBIAN AND FRIENDS,* I personally recommend that you execute the above command as the superuser via ```su```, so you're actually executing it as root.

######**If you run into build problems for wxPython:**
If you're using a distribution with the *apt* package manager, run this command:

    apt-get build-dep wx-common && apt-get install libwebkitgtk-3.0-dev 

Usage
============
####On Windows:
You can just click on quickCA.py or execute it from the command line.

####On Linux:
The same as above applies here as well. However, don't forget to:
	

    chmod a+x ./quickCA.py && chmod a+x ./launcher.sh

######**Linux-specific Usagii:**
There are a few ways to execute *quickCA* sanely under \*nix...

- * Execute ```./quickCA.py``` directly.

- * Use the __launcher__ ```./launcher.sh <path to filemanager executable>```

- * Say, *"Screw the launcher!"*, and do what it does manually thru: ```QC_FM=<path to filemanager executable> ./quickCA.py```

Installation
============
Normally, you'd just run ```./quickCA.py```, and be done with it; __however__, because I'd like for *quickCA* to be fully installable and usable within the Linux environment. There's a *Makefile* provided, so you can do it the kewl gmake way or the python way. __THE CHOICE IS YOURS!!!__ If you're planning to run from your */home dir* or whatnot, I recommend just ignoring this section. All this added complexity-- well, it's just to show my stuff off for you-- future employer... :wink:

<span>
<div style="position: relative; min-height: 56px; display: table; margin-left: 5%; background-color: rgba(111,122,144,0.25); background-size: cover; border: 2px dotted #880cde" id="inote-windoze"><p style="position: absolute; top: -24px; font-weight: bold; box-shadow: inset 0 -16px 0 0 rgba(188,94,255,0.33); background: linear-gradient(to bottom, #faeedf, rgb(188,94,255)); border-bottom: 3px solid rgba(111,122,144,0.75); padding-bottom: 1px; padding-left: 6px;">Check it out :</p><p style="position: relative; background-color: #909090; opacity: 0.44;"> == ***Windows users,***  *Feel free to skip over this section; it doesn't apply to y'all...* == :wave: :grinning: </p></div>
</span>

Replace the sub-command ```make locally``` with ```make install``` if you're planning to install **quickCA** to your system at *$PREFIX*... ... .. .*__Otherwise,__* run the below command before you execute the script:
	

    make && make locally


----------

<span>
<div style="max-width: 45%; min-width: 25%; min-height: 24px; max-height: 32px; border-left: 4px dotted #880cde; border-right: 4px dotted #880cde;">
<p style="font-weight: bold; box-shadow: inset 0 -16px 0 0 rgba(188,94,255,0.33); background: linear-gradient(to bottom, #faeedf, rgb(188,94,255)); border-bottom: 3px solid rgba(111,122,144,0.75); padding-bottom: 1px; padding-left: 6px;">JUST KEEP IN MIND :</p></div></span>

**MAKE LOCALLY == running from proj. directory**
**MAKE INSTALL == install to /usr/what/eva**
Changelog
============
These are essentially milestone versions, reflected by:  ```__version__``` and ```__version_info__``` respectively. Always assume that the latest version is ***master*** here on *tha git*  :grin:

#####**Latest Milestone: *0.0.9***

----------


* __0.0.9__ \- Root CA's (that are in a quickCA zip project can now be imported into the program
	* Some very minor UI cleanups
	* Groundwork laid for allowing altering of KeyUsage and ExtendedKeyUsage through the GUI.
* __0.0.8__ \- Exportation of genned CA's & inputted datas into a zip archive
	* Beginning-a-workings of allowing import of previous CA's genned with quickCA
* __0.0.7__ \- full generation of Root CA's into temp folder along w/ pub & priv keys.
