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
There does not appear to be any persistance in place with this one as there are mostly "open" and "load" entries and no "write".

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/8a4d2310-be66-4b30-9b23-e2d9079f37dc)


## **Under which conditions can you get the binary to exfiltrate data?**

To determine the first callback domain for this sample, inetsim must be running, and Wireshark needs to be active to capture the packets. This allows us to physically inspect the packets and identify the callback.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/1afffff8-a26f-49ef-bc26-44c5b85be949)

We are examining the first HTTP packet and opening up the header to inspect the associated URI, which informs us about the callback.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/715134a2-5de0-4bd1-9bed-6acd20fc1ccd)

I later discovered that using `grep` in FLOSS for the callback string would not yield results. The binary is splitting web requests between its first callback domain and the exfiltration domain.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/a62a78a2-246f-4a81-aa92-8aee01573fa0)

**Answer**: The binary must contact the domain of the callback that we just found to exfiltrate data. Failure to connect will result in the deletion of itself from disk.

## **What type of data is exfiltrated?**

The Cosmo.jpg picture is being exfiltrated to some sort of feed post on the URL that we found earlier.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/ca25b22e-69b3-4496-a24d-d9d8c06382f9)

## **What type of Encryption Algorithm is in use?**

One way to narrow it down is by checking if there's a reference to one in the strings. So, we will use FLOSS to `grep "RC4"` and we find a method call "toRC4". While this is just the surface, it's always best to go deeper to confirm that it is actually encrypted with RC4 in a more in-depth analysis phase.


![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/f243e102-e34c-4b88-867b-092fde1095c8)

To delve deeper, opening up the sample within Cutter would be a wise idea.
- In the nifty search field, we can look for the method call "toRC4."
- Find out where it begins.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/fc95ef2d-d730-4e13-8daf-64bccb3da7ee)

After an extensive search, we find where it begins!

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/c014c6be-4b6e-435d-a239-948c256332d3)

Another way to figure out the encryption is to load it up in Procmon and filter the Process Name to "unknown" and then the Operation type to "CreateFile."
- We can then see that there's a suspicious file created in the Public section of Users on the C drive, so we must track it down.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/480bc5d2-620f-452e-b6f0-5a1cc5ed9e12)

Physically tracking it down results in:
![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/4f6ed1bc-813c-40da-bd34-c8b92b253559)

Upon opening the file, which I learned later was a plaintext version of the password used for encryption.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/78fd61f3-521a-46da-b10f-f4b3dfa67c8d)

## **What is the significance of Houdini?**

Houdini is the method call that the binary uses to delete itself from the disk, aptly named as it disappears magically!

We can look up Houdini in Cutter, but to truly understand what's happening, we need to be viewing the main method. I recently learned that in Nim, there are multiple "main" methods.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/660bb88c-5598-4f0a-a754-a1b554aa3c7d)

In the above picture, you can see that we found Houdini in the MainModule method. There's a call to check the killswitch URL and test the contents of the `al` register (which represents the lower bits in the register). If the 0 flag is not set, then we jump to the call Houdini and then jump to the very end.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/2f4ddf11-e8d7-4aa4-ad5c-6323ce566fe8)

However, if checking the killswitch URL returns "True," then we follow a separate process.
- The contents of `rax` are checked, and if `rax` does not set the 0 flag, then we perform the functions that the malware is built to do, a sort of "business as usual" scenario. We can even see the reference to the `stealStuff` method.
- The opposite side calls Houdini, but it's in the event of it having been interrupted.
- Both paths continue to lead down to Houdini, and both result in it deleting itself from the disk, just after a difference in operations.

![image](https://github.com/CertainRisk/sikomode-challenge-MAT/assets/141761181/40e28916-fac4-454c-966c-8b630f40fb79)



