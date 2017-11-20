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
	

    chmod a+x ./quickCA.py

**(Linux Only)** Currently, for the *Explore Directory* menu option to you'll need to execute quickCA as follows:

    QC_FM=/path/to/your/fm ./quickCA.py
   
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
