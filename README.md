# NXP SE050 provisioning-cli

This is cli interface for provisioning NXP SE050 secure chip and ESP32  
by exchanging public key and certificate made with pem format.   
it's protected i2c transmission by PlatformSCP03 keys.   

# Requirements

  Platformio(PIO Core:4.3.1 PLATFORM: Espressif 32 1.11.1) with VS Code environment.  
  install "Espressif 32" platform definition on Platformio  

# Environment reference
  
  Espressif ESP32-DevkitC  
  this project initialize both of I2C 0,1 port, and the device on I2C port 0 is absent.  
  pin assined as below:  


      I2C 0 SDA GPIO_NUM_18
      I2C 0 SCL GPIO_NUM_19

      I2C 1 SDA GPIO_NUM_21
      I2C 1 SCL GPIO_NUM_22
          
  NXP SE050C1(on I2C port 1)  

  if you use other variants you need to change ENC, MAC, DEK key definition on port/ex_sss_auth.h]  

  Never use this code as production unless you change 3 keys to your own.  


# Usage

"git clone --recursive " on your target directory.  
and download "Plug & Trust MW Release v02.12.04" from NXP website  
and put the contents to "simw-top" folder.   
you need to change a serial port number which actually connected to ESP32 in platformio.ini.   

# Run this project

just execute "Upload" on Platformio.   

# CLI reference

"R"  
it returns "Ready." to make sure serial communication.   

"s"  
it returns UID of se050 encorded with base64.  

"k"  
it generates prime256v1 key pair and returns its public key as pem format.  

"v"  
device certificate accept mode.  
you can put pem formatted device cert after issuing this command.  
once it programmed, read it back from se050 and print the result for reference.  
this can't abort unless put "----END CERTIFICATE----"  

"c"  
signer CA certificate accept mode.  
you can put pem formatted device cert after issuing this command.  
once it programmed, read it back from se050 and print the result for reference.  
this can't abort unless put "----END CERTIFICATE----"  

"r"  
root CA certificate accept mode.  
you can put pem formatted device cert after issuing this command.  
once it programmed, read it back from se050 and print the result for reference.  
this can't abort unless put "----END CERTIFICATE----"  

"p"  
print 3 certificates of program buffer.  
please note it's not the contents of se050 internal memory.  

"q"  
quit this program.  

# Object ID Definitions

#define OBJID_usr_key (EX_SSS_OBJID_CUST_START + 0x10000002u)  
#define OBJID_usr_cert (EX_SSS_OBJID_CUST_START + 0x10000003u)  
#define OBJID_signer_cert (EX_SSS_OBJID_CUST_START + 0x10000004u)  
#define OBJID_root_cert (EX_SSS_OBJID_CUST_START + 0x10000005u)  


# License

This software is released under the MIT license unless otherwise specified in the included source code. See License. 
