# SikoMode Challenge 
From the Malware Analysis and Triage course offered by TCM Security, I will be documenting my experience with this challenge firsthand. :)

First, I am going to launch a PowerShell prompt from Cmder and figure out what the SHA256 file hash for the unknown sample is so that I may run it through VirusTotal to get a bit more information about it.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/946d0ad6-2abb-4c64-8382-69cccb7f65a3)

It didn't come up with anything on VirusTotal, so I shall move forward!

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/d31bc824-c461-4f7f-8633-bd9fb2045387)

For this challenge, there are also questions that need to be answered to help facilitate the learning experience.

## **The first question asked is what language is this binary written in?**
Upon using FLOSS, I was unable to determine which language was used as it all came out in ASCII. SO I decided to put it in PEview to get a better idea.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/6cf95cc1-ba0f-4d32-a0de-8eb192e29eb9)

In PEview, I was prompted with the message letting me know that it only provides a limited view of 64-bit files, so that lets me know that this is unlike the 32-bit files that I'm used to, which is a clue!

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/2970fdb5-1537-41c5-8f3c-7a0ec9a2ad27)

The SECTION .rdata I was able to see references to the Nim coding language. While there's always that chance that they threw in random strings to throw you off, I believe it's not in this case due to the frequency it's referenced.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/485f9767-dc7c-45bc-904f-b948a35dbaf0)

I later learned that PEStudio does support 64-bit files. Which brings me to the next question:
## **What architecture is this binary?**
- This is an x64 architecture binary for an x64-bit CPU.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/cd522f9a-1e3e-48b6-8dfe-13f43eeda13f)

Moving on to the Basic Static Analysis portion involves Remnux and of course inetsim in order to run the binary and see how it works while tricking it into thinking we are connected to the internet.

## **Under which conditions can you get this binary to delete itself?**

I find this particularly fun to test! To test this, we must have Remnux running inetsim and also have a separate tab for Wireshark to capture the TCP traffic and see what's going on.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/45428fac-4297-4e66-8fd9-b521510a0de4)

Everything is all hunky-dory and going green until we disable inetsim from running! It simply decides to spaz out and then deletes itself from disk, always exciting to see.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/0b239afc-8f21-4b29-a641-5aa2a4193992)

So we found so far that one condition is that it will delete itself if it cannot connect to the internet. Additionally, which makes sense but I didn't figure out until later is that another condition is that it will delete itself if it gets interrupted during whatever it is doing which goes along with the closing of the inetsim as its connection was interrupted.

## **Does the Binary persist, and if so, how?**

To figure this one out, I used Procmon to determine if there were any host-based indicators that might tell me something.

