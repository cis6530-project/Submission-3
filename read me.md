
---------------- install instructions -----------------------
For this section of the report we are using Ghidra due to its robust analysis capabilities aligning with the next step requirements of ML analysis

https://github.com/NationalSecurityAgency/ghidra



Following instructions we were directed to use related jdk 21 LTS \[x64 instance] Temurin 21.0.9+10-LTS - 10/23/2025

Ghidra Software Reverse Engineering Framework downloaded from NSA GitHub https://github.com/NationalSecurityAgency/ghidra?tab=readme-ov-file



\*copying the file extension pasting into firefox to download the related files\*



some trouble shooting was required due to multiple java versions - copilot noted to change jvm to the related java 21 for the jdk that we used.

*sudo update-alternatives --config java* 

allows you to change if required



next extract the ghidra instance and run for validation:
eg:
*mkdir -p ~/ghidra*

*unzip ghidra\_11.4.2\_PUBLIC\_20250826.zip -d ~/ghidra*


We run this headless for computational time hence:
*cd ~/ghidra/ghidra\_11.4.2\_PUBLIC/*

*chmod +x ghidraRun                    #Adds the executable bit to the ghidraRun script*

*chmod +x support/analyzeHeadless      #analyzeHeadless is the headless-mode launcher you use to run Ghidra from the command line needed for this automation*



to test it installed properly:
*./ghidraRun*



------------------details for operating opcode generation .py----------------------------
modifying OpCodeReverseTool to operate as an all in one py that will work with previous Powershell file explorer script (in progress) add filepath and this will output - https://github.com/louiskyee/OpCodeReverseTool


* CSV as original provided in the GitHub \[modded] to allow easy visualization
* .opcode file that is required for P3 submission



required installs:
*python3 -m pip install tqdm*







python3 your\_script.py


/root/Desktop/Submission-2-main/Executable Malware



python3 /root/ghidra/ghidra\_opcode\_script.py \\

&nbsp; -d "/root/Desktop/Submission-2-main/Executable Malware" \\

&nbsp; -g /root/ghidra/ghidra\_11.4.2\_PUBLIC/support/analyzeHeadless \\

&nbsp; -o "/root/Desktop/Submission-2-main/Executable Malware\_disassemble" \\

&nbsp; --include-all



python3 /root/ghidra/ghidra\_opcode\_script.py \\

&nbsp; -d "/root/Desktop/Submission-2-main/Executable Malware" \\

&nbsp; -g /root/ghidra/ghidra\_11.4.2\_PUBLIC/ghidra/support/analyzeHeadless" \\

&nbsp; -o "/root/Desktop/Submission-2-main/Executable Malware\_disassemble" \\

&nbsp; --include-all





python3 /root/ghidra/ghidra\_opcode\_script.py -d "/root/Desktop/Submission-2-main/Executable Malware" -g /root/ghidra/ghidra\_11.4.2\_PUBLIC/ghidra/support/analyzeHeadless -o "/root/Desktop/Submission-2-main/Executable Malware\_disassemble" --include-all



