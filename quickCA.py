#!/usr/bin/python3
# coding: utf-8
#
# quickCA.py ~ a GUI for fast certificates- legitimate or otherwise
# (C) 2017 Matthew E. Kehrer <matthew@kehrer.pro>
#	~ ~ This script is open source software according to GNU LGPL ~ ~
# DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
##.DEPENDENCIES.............................................
# wxPython, certbuilder, cryptography, oscrypto, asn1crypto
##..........................................................
# DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
# changelog:
# 0.0.9 - Root CA's (that are in a quickCA zip project can now be import
#			-ed into the program
#		- - Some very minor UI cleanups
#		- - Groundwork laid for allowing altering of KeyUsage and
#			  ExtendedKeyUsage through the GUI.
# 0.0.8 - Exportation of genned CA's & inputted datas into a zip archive
#		- - Beginning-a-workings of allowing import of previous CA's...
#		- - genned with quickCA
# 0.0.7 - full generation of Root CA's into temp folder along w/
#			pub & priv keys.
import os
import secrets
import logging
import tempfile
import shutil
import re
from contextlib import contextmanager
import zipfile
from zipfile import ZipFile
import json
import subprocess

#@ ya betta istall
#@@,,.WXPYTHON from WXWINDOWS
#@
import wx
import wx.lib.newevent
import wx.lib.dialogs as wx_dialogs
import wx.lib.agw.supertooltip as wx_stt
#@ ya betta istall
#@@,,.CERTBUILDER from the pypi
#@
import certbuilder
from certbuilder import CertificateBuilder
#@ y betta istall
#@@,,.CRYPTOGRAPHY & OSCRYPTO & ASN1CRYPTO libs
#@
import cryptography.x509.extensions as x509_ext
import cryptography.x509.oid as x509_oid
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import asn1crypto.x509 as x509_asn1
from oscrypto import asymmetric

# ## verinfo ## #
__version__ = '0.0.9'
__version_info__ = (0, 0, 9)

# ## GLOBALSsss ## #
MainWindow = None
FaylDialog = None
UpdateKeyUsages, EVT_UPDATE_KUS_EVENT = wx.lib.newevent.NewEvent()

#### Support for the common Extended Key Usage fields found in x509
# member self.OIDs is of type: cryptography.x509.oid.ObjectIdentifier
#
class QCertEKU(object):
	def __init__(self, server_auth=True, client_auth=True, code_sign=False, emailing=True, timestamp=True, ip_sec=(False,False,False)):
		self.OIDs = []
		self.BoolParams = []
		ls_eku = self._create_ls_eku(server_auth, client_auth, code_sign, emailing, timestamp, ip_sec[0], ip_sec[1], ip_sec[2])
		
		i = 0
		for (o,c) in ls_eku.items():
			# This is for self.BoolParams
			i += 1
			if (i <= 5) and not (i == 6):
				self.BoolParams.append(tuple((int(i),bool(c))))
			elif (i >= 6) and not (i > 8):
				self.BoolParams.append(tuple((int(i|0xFA000000),bool(c))))
			
			# This is for self.OIDs
			if c is True:
				self.OIDs.append(x509_oid.ObjectIdentifier(o))
		
	def __repr__(self):
		return "<QCertEKU(OIDs={0.OIDs})>".format(self)

	# creates precursor OID str-bool dict object
	def _create_ls_eku(self, server_auth, client_auth, code_sign, emailing, timestamp, ip_sec_a, ip_sec_b, ip_sec_c):
		return dict(
			{
				'1.3.6.1.5.5.7.3.1': bool(server_auth),
				'1.3.6.1.5.5.7.3.2': bool(client_auth),
				'1.3.6.1.5.5.7.3.3': bool(code_sign),
				'1.3.6.1.5.5.7.3.4': bool(emailing),
				'1.3.6.1.5.5.7.3.8': bool(timestamp),
				'1.3.6.1.5.5.7.3.5': bool(ip_sec_a), # IP SEC END
				'1.3.6.1.5.5.7.3.6': bool(ip_sec_b), # IP SEC TUNNEL
				'1.3.6.1.5.5.7.3.7': bool(ip_sec_c), # IP SEC USER
			}
		)
	
	# RETURNS a set of enabled OIDs as strings
	def getOIDSet(self):
		retme = set()
		for x in range(0,len(self.OIDs)):
			retme.add(self.OIDs[x].dotted_string)
		
		return retme
	# RETURNS a string of set EKU's for the tooltip
	def boolString(self):
		blist = []
		for (i, b) in self.BoolParams:
			blist.append(b)
		bstr = "SA: %s CA: %s CS: %s E-M: %s TS: %s IPEND: %s IPTUN: %s IPUSR: %s" % (blist[0], blist[1], blist[2], blist[3], blist[4], blist[5], blist[6], blist[7])
		return bstr

####  Our temporary working folder
# Temp folder
class QCWorkspace(tempfile.TemporaryDirectory):
	def __init__(self, *args, **kwargs):
		super(QCWorkspace, self).__init__(suffix=None, prefix='tmpQC', dir=None,*args,**kwargs)
		
		# members
		## path
		ws = str(self).rstrip('\'>').split(' ') # stringify self needs to be formatted properly
		self.Workspace = ws[1].strip('\'') #    # cus we just want the string value of fully qual'ed
		
	def __del__(self):
		super(QCWorkspace, self).cleanup()
		return

	def getWorkspace(self):
		return self.Workspace
	
	def pathForFile(self, filename):
		return '{0}/{1}'.format(self.getWorkspace(),filename)

#### Our Window
# Window
#
# ## TODO L8er: Allow pick & choosing KeyUsage and ExKeyUsage values
#
class QCWindow(wx.Frame):
	def __init__(self, *args, **kwargs):
		super(wx.Frame, self).__init__(None,id=wx.ID_ANY, pos=wx.DefaultPosition, title='QUICKCA - Root CA & Cert Gen', size=wx.DefaultSize,style=wx.DEFAULT_FRAME_STYLE,name='MainWindow')
		
		# controlz with info
		self.city_state_cunt = None
		self.common_organ = None
		self.defaultpass = None
		# controls with 'ventzzz
		self.gen_ca = None
		self.btn_tipku = None
		self.btn_tipeku = None
		
		#menu
		self.mainmenu = self.createMainMenu()
		self.SetMenuBar(self.mainmenu)
		self.mainmenu.Refresh()
		
		#tips
		self.tippy_ku = self.createTooltips()
		self.tippy_eku = self.createTooltips()
		
		#data
		self.data_keyusage = x509_ext.KeyUsage(True,True,True,True,True,True,True,True,True)
		self.data_exkeyusage = QCertEKU(True,True,True,True,True,(True,True,True))
		self.data_wspace = None
		self.data_ca_made = False
		self.data_ca_props = dict()
		
		self.createControls()
		wx.PostEvent(self, UpdateKeyUsages())
	
	### Array of fields for certbuilder
	# # # (L)LOCALITY -> (ST)STATE -> (C)COUNTRY -> (CN) COMMON-NAME -> (O)ORGANIZATION
	def fieldsfromInput(self, csc, cooo):
		both_inputs = ",".join([csc, cooo])
		# regex below to divide strings by ',' || ', '
		return re.split('\,[\,\ +]*', both_inputs)
	
	### Ради Дата ###
	# workspace
	def setWorkspace(self, ws):
		self.data_wspace = ws
		return
	def hasWorkspace(self):
		if self.data_wspace is None:
			return False
		return True
	# CA cert -> genned / loaded (T or F)
	def genned_ca(self, da):
		self.data_ca_made = da
	
	### GUI funcs ###
	# create mainmenu
	def createMainMenu(self):
		mbar = wx.MenuBar()
		menu = wx.Menu()
		saveitem = wx.MenuItem(menu,9100,'&Save Workspace','Save the active workspace to *.zip')
		self.Bind(wx.EVT_MENU, self.OnFileSave, saveitem)
		exploreitem = wx.MenuItem(menu, 9101, 'Explore &Directory', 'Explore the workspace directory')
		self.Bind(wx.EVT_MENU, self.OnFileExplore, exploreitem)
		exititem = wx.MenuItem(menu,9102,'E&xit','...ahem...')
		self.Bind(wx.EVT_MENU, self.OnFileExit, exititem)
		menu.Append(saveitem)
		menu.Append(exploreitem)
		menu.AppendSeparator()
		menu.Append(exititem)
		mbar.Append(menu,'&File')
		
		
		return mbar
	# create tooltips
	def createTooltips(self):
		return wx_stt.SuperToolTip("")	
	# create controls
	def createControls(self):
		self.SetBackgroundColour(wx.Colour(240,240,240))
		panel = wx.Panel(self)
		pan_box = wx.GridBagSizer(8,4)

		# First prompt
		pan_box.Add(wx.StaticText(self, -1, "Enter below information (comma separated) for gen\'d root CA:"),pos=(0,0),flag=wx.EXPAND|wx.TOP|wx.LEFT,border=2)
		# CA CSC
		self.city_state_cunt = wx.TextCtrl(panel, -1, value="CITY, STATE, COUNTRY",name='city_state_cunt')
		self.city_state_cunt.SetMinSize(wx.Size(self.city_state_cunt.GetSize()[1]*16,wx.DefaultCoord))
		self.city_state_cunt.SetInsertionPoint(0)
		self.city_state_cunt.SetEditable(True)
		pan_box.Add(self.city_state_cunt,pos=(1,0),flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.RIGHT|wx.LEFT,border=4)
		# CA CO OO
		self.common_organ = wx.TextCtrl(panel, -1, value="COMMON NAME, ORGANIZATION NAME",name='common_organ')
		self.common_organ.SetMinSize(wx.Size(self.common_organ.GetSize()[1]*16,wx.DefaultCoord))
		self.common_organ.SetInsertionPoint(0)
		self.common_organ.SetEditable(True)
		pan_box.Add(self.common_organ, pos=(2,0),flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.RIGHT|wx.LEFT,border=4)
		
		# second prompt
		pan_box.Add(wx.StaticText(self, 32666, "Key Usage:",style=wx.ALIGN_LEFT),pos=(3,0),flag=wx.EXPAND|wx.LEFT|wx.RIGHT,border=2)
		self.FindWindow(32666).Enable(False)
		self.FindWindow(32666).SetBackgroundColour(wx.Colour(192,192,197))
		###TODO: LET USR PICK THIS STUFF
		# KeyUsage Tooltip button
		self.btn_tipku = wx.Button(panel, -1, label="♠", style=wx.BORDER_NONE|wx.BU_EXACTFIT, name='btn_tipku')
		self.btn_tipku.SetBackgroundColour(wx.Colour(0,0,140))
		self.btn_tipku.SetForegroundColour(wx.Colour(192,232,255))
		self.Bind(wx.EVT_BUTTON, self.OnTipKU, self.btn_tipku)
		pan_box.Add(self.btn_tipku, pos=(3,1))
		###TODO: LET USR PICK THIS STUFF
		pan_box.Add(wx.StaticText(self, 32664, "(ALL ENABLED)",style=wx.ALIGN_CENTRE|wx.ALIGN_LEFT),pos=(3,2),flag=wx.EXPAND|wx.RIGHT,border=2)
		self.FindWindow(32664).Enable(False)
		self.FindWindow(32664).SetBackgroundColour(wx.Colour(192,192,197))
		# third prompt
		pan_box.Add(wx.StaticText(self, 32662, "Extended Key Usage:",style=wx.ALIGN_LEFT),pos=(4,0),flag=wx.EXPAND|wx.LEFT|wx.RIGHT,border=2)
		self.FindWindow(32662).Enable(False)
		self.FindWindow(32662).SetBackgroundColour(wx.Colour(192,192,197))
		###TODO: LET USR PICK THIS STUFF
		# ExKeyUsage Tooltip button
		self.btn_tipeku = wx.Button(panel, -1, label="♠", style=wx.BORDER_NONE|wx.BU_EXACTFIT, name='btn_tipeku')
		self.btn_tipeku.SetBackgroundColour(wx.Colour(0,0,140))
		self.btn_tipeku.SetForegroundColour(wx.Colour(192,232,255))
		self.Bind(wx.EVT_BUTTON, self.OnTipEKU, self.btn_tipeku)
		pan_box.Add(self.btn_tipeku, pos=(4,1))
		###TODO: LET USR PICK THIS STUFF
		pan_box.Add(wx.StaticText(self, 32660, "(ALL ENABLED)",style=wx.ALIGN_CENTRE|wx.ALIGN_LEFT),pos=(4,2),flag=wx.EXPAND|wx.RIGHT,border=2)
		self.FindWindow(32660).Enable(False)
		self.FindWindow(32660).SetBackgroundColour(wx.Colour(192,192,197))
		
		# DEFAULT PASS?
		self.defaultpass = wx.CheckBox(panel, -1, label="Use default pass: \'password\'?",style=wx.ALIGN_LEFT|wx.CHK_2STATE,name='defaultpass')
		self.defaultpass.SetValue(True)
		pan_box.Add(self.defaultpass, pos=(5,0),flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.RIGHT|wx.LEFT,border=2)
		
		# GEN CA BUTTON
		self.gen_ca = wx.Button(panel,-1,label="GENERATE CA",style=wx.ALIGN_RIGHT,name='gen_ca')
		self.Bind(wx.EVT_BUTTON, self.onClick_GenCA, self.gen_ca)
		pan_box.Add(self.gen_ca,pos=(5,1),flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.RIGHT|wx.LEFT,border=2)
		pan_box.SetItemSpan(self.gen_ca, wx.GBSpan(1,2)) #	## Keep our GUI somewhat pretty
		
		# put erry thang in sizer
		panel.SetSizerAndFit(pan_box)
		
		# ENSURE WINDOW IS THE PROPER SIZE
		@contextmanager
		def colwidths(next):
			yield self.defaultpass.GetSize()[0]+next.GetSize()[0]
		# # #
		# We wanna be wide enuf 4 the checkbox,its caption,and our [Gen CA] button
		#    plus 48px of padding- it turnt out good :^)
		with colwidths(self.gen_ca) as j:
			j += 48 # jus sum padding
			self.SetMinSize(wx.Size(j,wx.DefaultCoord))
			panel.SetMinSize(wx.Size(j,wx.DefaultCoord))
			self.Fit() # /_!_\ The magic happens here
		#			   # CALL SELF.FIT() SO WX DOES SHIT RIGHT
		#			   # Lesson learned.......
		
		# link our custom event handler here
		self.Bind(EVT_UPDATE_KUS_EVENT, self.OnUpdateKeyUsages)
		# setup our tooltips
		self.tippy_ku.SetHeader("KeyUsage Fields:")
		self.tippy_eku.SetHeader("ExtendedKeyUsage Fields:")
		self.tippy_ku.SetDrawHeaderLine(True)
		self.tippy_eku.SetDrawHeaderLine(True)
		self.tippy_ku.SetTarget(self.btn_tipku)
		self.tippy_eku.SetTarget(self.btn_tipeku)
		
		self.SetAutoLayout(True)
		
	def onClick_GenCA(self, event):
		# One single array for our input x509 subject fields
		@contextmanager
		def cbuilder_array(t0, t1):
			yield self.fieldsfromInput(t0.GetLineText(0),t1.GetLineText(0))
		# x509 passphrase.
		# # either password or user-defined.
		@contextmanager
		def giveth_pass(default):
			booldefault = default.GetValue()
			if booldefault is True:
				yield 'password'
			elif booldefault is False:
				yield wx_dialogs.textEntryDialog(self,"Enter thou art\'s most secret pass-phrase:\nIf thee wisheth, ye may utilise the default: \'password\'.","Input thy pass-phrase:",'password',wx.OK|wx.CANCEL|wx.TE_PASSWORD).text
		
		# # done with these with-decls above
		### THE MEAT OF ONCLICK_GENCA
		with cbuilder_array(self.city_state_cunt,self.common_organ) as certbuildInput:
			with giveth_pass(self.defaultpass) as thePassword:
				#format our keyusage for asn1's silly bitstring derivative
				asn1ku = FormatKeyUsage(self.data_keyusage)
				print("\nStarting Root CA generate...\n")
				print(certbuildInput)
				print("---")
				#print(self.data_keyusage)
				#print("---")
				#print(asn1ku)
				#print("---")
				#print(self.data_exkeyusage)
				print("\n")
				print("GENERATING RSA+RSA keypair (4096-bit)...")
				# GENERATE & DUMP RSA KEYS
				ca_pub, ca_priv = asymmetric.generate_pair('rsa',bit_size=4096)
				f = os.open(self.data_wspace.pathForFile('ca_priv.key'),os.O_CREAT|os.O_RDWR|os.O_BINARY)
				f2 = os.open(self.data_wspace.pathForFile('ca_pub.key'),os.O_CREAT|os.O_RDWR|os.O_BINARY)
				os.write(f, asymmetric.dump_private_key(ca_priv,thePassword))
				os.write(f2, asymmetric.dump_public_key(ca_pub))
				os.fsync(f)
				os.fsync(f2)
				os.close(f)
				os.close(f2)
				print("DUMPED TO:\n\t{0}\n\t{1}".format(self.data_wspace.pathForFile('ca_priv.key'),self.data_wspace.pathForFile('ca_pub.key')))
				print("Now creating cert...")
				# Build the certificate!!!!!!!!!!!!!!!!!
				builder = CertificateBuilder(
					{
						'locality_name': certbuildInput[0],
						'state_or_province_name': certbuildInput[1],
						'country_name': VerifyCorrectCountryName(certbuildInput[2]),
						'common_name': certbuildInput[3],
						'organization_name': certbuildInput[4],
					},
					ca_pub
				)
				builder.self_signed = True # SELF-SIGNED
				builder.ca = True #		   # CERTIFICATE AUTHORITY
				builder._key_usage = asn1ku		 # OVERRIDE certbuilder's KU WITH OURS'
				builder.extended_key_usage = self.data_exkeyusage.getOIDSet() # Set&Save our ExtendedKeyUsagii here
				builder.serial_number = CreateSerialNumber() # 			# We be of needin's a serial, lads
				ca_certificate = builder.build(ca_priv)
				f3 = os.open(self.data_wspace.pathForFile('root_ca.crt'),os.O_CREAT|os.O_RDWR|os.O_BINARY)
				os.write(f3, certbuilder.pem_armor_certificate(ca_certificate))
				os.fsync(f3)
				os.close(f3)
				print("SAVED ROOT CA :-) :\n\t{0}".format(self.data_wspace.pathForFile('root_ca.crt')))
				# SAVE THE SERIAL AS A .SRL
				f5 = os.open(self.data_wspace.pathForFile('root_ca.srl'),os.O_CREAT|os.O_RDWR|os.O_BINARY)
				self.data_ca_props = dict(
					{
						'subject_fields': certbuildInput,
						'keyusage': asn1ku,
						'extkeyusage': self.data_exkeyusage.getOIDSet(),
						'serial_no': builder.serial_number,
						'pub_key': ca_pub,
						'priv_key': ca_priv,
					},
				)
				# SRL SAVE HAPPENS HERE m80
				cereal = "%X" % (self.data_ca_props['serial_no'])
				os.write(f5, cereal.encode())
				os.fsync(f5)
				os.close(f5)
				# OUTPUT USER CUSTOMIZATIONS TO A JSON FILE
				with open(self.data_wspace.pathForFile('build.json'), 'w+') as f4:
					json.dump(
						{
							"fields": certbuildInput,
							"extkeyusage": self.data_exkeyusage.BoolParams,
							"prk_name": "ca_priv.key",
							"puk_name": "ca_pub.key",
							"crt_name": "root_ca.crt",
						},
						f4,
						indent=5
					)
				
				print("\nSUCCESS!!! You can now export your newly forged Root CA via `Save Workspace` under `File`.")
		
		return self.genned_ca(True)
	
	def OnFileExit(self, *event):
		self.Close()
	
	def OnFileExplore(self, *event):
		try:
			try:
				# Windows? Oh, well this is easy then....
				if any([lambda: os.name == 'nt', os.name == 'ce']) is True or all([lambda: 'win' in sysconfig.get_platform()]) is True:
					subprocess.call(['explorer', '.'],cwd=os.path.normcase(self.data_wspace.getWorkspace()))
				else:
					# Must be Linux or w/e
					# # hope it's Linux, i can't afford no macintosh
					subprocess.call(['/usr/bin/thunar', '.'],cwd=os.path.normcase(self.data_wspace.getWorkspace()))
				
			except FileNotFoundError:
				spurdo  = ':3o'
				fileman = os.getenv('QC_FM', spurdo)
				
				if (fileman == spurdo):
					raise ValueError()
				else:
					subprocess.call([fileman, '.'],cwd=os.path.normcase(self.data_wspace.getWorkspace()))
			
		except ValueError:
			print ("!!!ERROR!!!:: quickCA can't execute a file manager. Please export env var \"QC_FM=your fm\"")
		
		return
	
	def OnFileSave(self, *event):
		#orig dir
		@contextmanager
		def originaledir():
			yield os.getcwd()
		
		if self.data_ca_made is not False:
			savewhere = wx_dialogs.saveFileDialog(self,wildcard='ZIP Archive (*.zip)|*.zip')
		else:
			wx_dialogs.alertDialog(self,message='Ye hath yet to generate anything that is worth saving, m\'lord.')
			return
		# #
		# Create tha archive!
		with originaledir() as OG:
			os.chdir(os.path.normcase(self.data_wspace.getWorkspace()))
			shutil.make_archive(savewhere.paths[0],"zip",root_dir=None,base_dir=None)
			os.chdir(OG)
		
		return
	
	def OnUpdateKeyUsages(self, *event):
		self.tippy_ku.SetMessage(ToolTippifyKeyUsage(self.data_keyusage))
		self.tippy_eku.SetMessage(self.data_exkeyusage.boolString())
		return
	
	def OnTipKU(self, event):
		self.tippy_ku.Show(True)
		return
	
	def OnTipEKU(self, event):
		self.tippy_eku.Show(True)
		return
	
#### >functional language
#### >no goto's
#    >implying
class GOTOO(Exception):
	pass

## SERIAL-NO. GENERATE
# generate a cert's serial
def CreateSerialNumber():
	return ((secrets.randbits(32) & 0xFFFFFFFF) << 32) | secrets.randbits(32)

## ENSURE country_name field is correctly formatted
# it should be all caps and 2 chars in length
def VerifyCorrectCountryName(countrynam):
	if (len(countrynam) == 2):
		return countrynam.upper()
	return '{0:2}'.format(countrynam.upper())

### KEYUSAGE to asn1rypto's Integer/BitString converter
# certbuilder uses asn1crypto which just uses int's for KeyUsage
# # this converts cryptography's to asn1's
def FormatKeyUsage(cku):
	if not isinstance(cku, x509_ext.KeyUsage):
		raise TypeError(unwrap(
			'''
			Param -> cku MUST BE cryptography.x509.extensions.KeyUsage!!!
			    %s is incorrect type for Param cku!!!
			''',
			type_name(cku)
		))
	if cku._digital_signature is False:
		raise TypeError(unwrap(
			'''
			HOW DO YOU PLAN ON USING A CERT THAT CAN'T DIGITAL SIG?!?!
			'''
		))
	
	beans = [cku._digital_signature,cku._content_commitment,cku._key_encipherment,cku._data_encipherment,cku._key_agreement,cku._key_cert_sign,cku._crl_sign,cku._encipher_only,cku._decipher_only]
	teans = []
	i = '0'
	for b in beans:
		if b is True:
			i = '1'
		else:
			i = '0'
		teans.append(int(i,base=2))
	
	asn1ku = x509_asn1.KeyUsage()
	asn1ku.set(tuple(teans))
	return asn1ku

### KEYUSAGE to friendly tooltip string
# nothing too fancy here
def ToolTippifyKeyUsage(keyusago):
	def field_text(label, value):
		return "%s: %s" % (label, value)
	
	if not isinstance(keyusago, x509_ext.KeyUsage):
		raise TypeError()
	
	lstrl = []
	lstrl.append(field_text('DSIG', keyusago._digital_signature))
	lstrl.append(field_text('CC', keyusago._content_commitment))
	lstrl.append(field_text('KEYEN', keyusago._key_encipherment))
	lstrl.append(field_text('DATEN', keyusago._data_encipherment))
	lstrl.append(field_text('KEYAG', keyusago._key_agreement))
	lstrl.append(field_text('CRTSIG', keyusago._key_cert_sign))
	lstrl.append(field_text('CRLSIG', keyusago._crl_sign))
	lstrl.append(field_text('ENCONL', keyusago._encipher_only))
	lstrl.append(field_text('DECONL', keyusago._decipher_only))
	
	return ' '.join(lstrl)

############################################################
#``````` ACTUAL PROGRAM FLOW IS BELOW ```````
############################################################

#### OUR FIRST-RUN SETUP
def OFirstSetup(tupleWindoze):
	fselw = tupleWindoze[0] # file selector / None
	windo = tupleWindoze[1] # MainWindow
	
	if fselw is not None:
		ws = QCWorkspace()
		windo.setWorkspace(ws)
		# load zip that was chosen
		zippy = ZipFile(fselw.paths[0],"r",zipfile.ZIP_STORED|zipfile.ZIP_DEFLATED)
		zippy.extractall(ws.getWorkspace())
		del zippy
		# load root cert from the archive
		existing_ca = None
		with open(ws.pathForFile('root_ca.crt'),'rb') as cfx:
			existing_ca = x509.load_pem_x509_certificate(cfx.read(), default_backend())
		# load the `build.json` file
		json_data = None
		with open(ws.pathForFile('build.json'), 'r') as jayson:
			json_data = json.load(jayson)
		
		# Now, we shall ferry all this junk to it's proper home here :)
		#
		## KEYUSAGE
		# Simply load this from the Root CA crt file
		nouku = None
		try:
			nouku = existing_ca.extensions.get_extension_for_class(x509_ext.KeyUsage)
			nouku = nouku.value
		except TypeError:
			print ("!!!ERROR!!!:: No KeyUsage Found!\n\tUSING DEFAULT: All TRUEs...")
			nouku = windo.data_keyusage
		finally:
			if nouku is not None:
				windo.data_keyusage = nouku
		
		## EX. KEY USAGE
		# ExKeyUsage vals NOT related to ipsec
		a = list(filter(lambda x: not (x[0]&0xFA000000), json_data['extkeyusage']))
		a = list(map(lambda x: x[1], a)) # 		### isolate
		# The opposite condition to above's
		b = list(filter(lambda x: x[0]&0xFA000000, json_data['extkeyusage']))
		b = list(map(lambda x: x[1], b)) #		### isolate 
		# OVERWRITE & CHANGE THE EKU-class with the loaded stuffs values
		del windo.data_exkeyusage
		windo.data_exkeyusage = QCertEKU(a[0],a[1],a[2],a[3],a[4],(b[0],b[1],b[2]))
		
		## SUBJECT FIELDS
		# we want the list as a list but then...
		# # WE ALSO want to create nifty strings for the GUI
		a = json_data['fields']
		csc = ', '.join(a[0:3])				 # ## NIFTY STRINGS!
		cno = ', '.join(a[3:5])
		# ## mr. miyada, my PyFu improves with evry line!
		windo.city_state_cunt.ChangeValue(csc)
		windo.common_organ.ChangeValue(cno)
		
		#-#-## Done with the loading!
		# # ## DISABLE THE "GENERATE CA" Button
		windo.genned_ca(True)
		windo.gen_ca.Disable()
		windo.gen_ca.SetLabel("[LOADED CA.]")
		# Update tooltips
		wx.PostEvent(windo, UpdateKeyUsages())

	return

#### OUR FIRST-RUN SETUP (2/2)
##
# - MainWindow IS CREATE HEEERE
# Oh so awesome recursivity
##
def OFirstQuesto():
	global MainWindow
	global FaylDialog
	a = None
	b = None
	
	try:
		if MainWindow is None:
			que = wx.GenericMessageDialog(None,"Would you like to generate a New Root CA?\nOr, Would you like to load existing CA? Using it for QuickCA???\n\nDefault\'s YES.", caption='QuickCA', style=wx.YES_NO|wx.CENTRE)
			ans = que.ShowModal()
			que.Destroy()
			if (ans == wx.ID_YES):
				b = MainWindow = QCWindow()
				a = FaylDialog
			else:
				a = FaylDialog = wx_dialogs.openFileDialog(None, style=wx.FD_OPEN, wildcard='ZIP Archives (*.zip)|*.zip')
				b = MainWindow = QCWindow()
		else:
			a = FaylDialog
			b = MainWindow
			raise GOTOO()
	except GOTOO:
		return (a,b)
	
	return OFirstSetup(OFirstQuesto())

#### MAIN ##############################################
def Main():
	global MainWindow
	# setup wx
	logging.basicConfig()
	app = wx.App(redirect=False)

	# setup workspace
	wspace = QCWorkspace()
	print("Working in: {0}".format(wspace.getWorkspace()))

	# aSK THE QUESTION AND CREATE MAINWINDOW
	OFirstQuesto()
	MainWindow.Show()
	if MainWindow.hasWorkspace() is False:
		MainWindow.setWorkspace(wspace)
	else:
		wspace = MainWindow.data_wspace
		print("WAIT... NOW Working in: {0}".format(MainWindow.data_wspace.getWorkspace()))

	# EVENT LP
	app.MainLoop()
	wspace.cleanup()
	
####: #ENTRY ###########################################
if __name__ == '__main__':
	Main()
