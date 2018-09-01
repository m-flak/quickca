# **quickCA**
> a GUI for fast certificates- legitimate or otherwise

quickCA is a Python GUI application written for the purpose of generating Root Certificate Authorities and processing any CSRs to generate certificates, quickly. *Yes, quickly. No fuss with OpenSSL switches and whatnot... __With quickCA, generate them quickly whether it be legitimate or otherwise__* 

<p align=center><u>Table of Contents</u>
    <a href="#dependencies">Dependencies</a>
    <a href="#usage">Usage</a>
    <a href="#installation">Installation</a>
    <a href="#changelog">Changelog</a>
</p>

## Dependencies

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

###### **If you run into build problems for wxPython:**
If you're using a distribution with the *apt* package manager, run this command:

    apt-get build-dep wx-common && apt-get install libwebkitgtk-3.0-dev 

## Usage

#### On Windows:
You can just click on quickCA.py or execute it from the command line.

#### On Linux:
The same as above applies here as well. However, don't forget to:
	

    chmod a+x ./quickCA.py && chmod a+x ./launcher.sh

###### **Linux-specific Usages:**
There are a few ways to execute *quickCA* sanely under \*nix...

- * Execute ```./quickCA.py``` directly.

- * Use the __launcher__ ```./launcher.sh <path to filemanager executable>```

- * Say, *"Screw the launcher!"*, and do what it does manually thru: ```QC_FM=<path to filemanager executable> ./quickCA.py```

## Installation

Normally, you'd just run ```./quickCA.py```, and be done with it; __however__, because I'd like for *quickCA* to be fully installable and usable within the Linux environment. There's a *Makefile* provided. If you're planning to run from your */home dir* or whatnot, I recommend just ignoring this section.

Replace the sub-command ```make locally``` with ```make install``` if you're planning to install **quickCA** to your system at *$PREFIX*... ... .. .*__Otherwise,__* run the below command before you execute the script:
	

    make && make locally

###### **JUST KEEP IN MIND**

**MAKE LOCALLY == running from proj. directory**
**MAKE INSTALL == install to /usr/what/eva**

## Changelog

These are essentially milestone versions, reflected by:  ```__version__``` and ```__version_info__``` respectively. Always assume that the latest version is ***master*** here on *tha git*  :grin:

##### **Latest Milestone: *0.0.9***

----------

* __0.0.9__ \- Root CA's (that are in a quickCA zip project can now be imported into the program
	* Some very minor UI cleanups
	* Groundwork laid for allowing altering of KeyUsage and ExtendedKeyUsage through the GUI.
* __0.0.8__ \- Exportation of genned CA's & inputted datas into a zip archive
	* Beginning-a-workings of allowing import of previous CA's genned with quickCA
* __0.0.7__ \- full generation of Root CA's into temp folder along w/ pub & priv keys.
