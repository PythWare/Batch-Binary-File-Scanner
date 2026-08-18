# Kybernes Batch Binary File Scanner

This is a standalone GUI Batch Binary File Scanner I made in Python to make finding data/text significantly easier/quicker. Instead of you having to open thousands of files 1 by 1 in a hex editor (which would be time consuming) to search for 1 thing, you can use this. It even supports usage of multiprocessing, meaning you can use your extra cores to have many workers scanning to speed up the scanning.

The tool will scan all files within a directory you select including subdirectories, it also tells you the file and the offsets of what you searched was found at. It accepts hex or text for searches. You can also select the character encoding to use for searching when using text searches. The current encodings I have supported are utf-8, shift-jis, and big-5. If you want support for more encodings, let me know. Shift-Jis is the most common character encoding for Japanese text in Japanese games and Big-5 for Chinese developed games, this will make finding Japanese/Chinese dialogue a lot easier if you originally had thousands of files you had to open manually, instead just type in what you want and have the scanner search for you.

I also included compression searching, the only algorithm I added support for is ZLIB which uses deflate. Compression searching means it will compress your text/bytes with ZLIB and search for the compressed version. If enough people are interested in compression searching, i'll add support for other compression algorithms.

Wildcard scanning is also supported, if you know part of the data to something but not all of it, you can use wildcards inplace of values you don't know. This scanner uses ?? as a wildcard, for any byte values you don't know you can use ?? to replace the value you're missing.

This tool can be used for any game/files. 

You need Python 3 installed to use this.

# Extra Info

Kybernes Batch File Scanner will use up to 50 MB for ram per worker. So if you only need to do a small scan and you can't spare at least a gigabyte of ram, leave CPU cores to use blank or set to 1. If you set it to 2 or higher, each worker will use up to 50 MB. Since I have 16 cores, that means 800 MB of ram would be used during the scanning with 16 workers.

I suggest setting CPU cores to use when you can spare the ram because it significantly speeds up the scanning process and if you need to scan hundreds of thousands of files, it's pretty damn useful having multiple workers scanning.

# Array of byte scan example

<img width="1251" height="731" alt="kyb2" src="https://github.com/user-attachments/assets/458781e5-644c-4a47-ae75-afc0acedb7c7" />

<img width="1251" height="730" alt="kyb3" src="https://github.com/user-attachments/assets/8237d16f-5b8d-498b-a41e-1600d8c110cd" />

# Wildcard searching example:

<img width="1247" height="731" alt="kyb5" src="https://github.com/user-attachments/assets/87a5bda6-880e-4fda-8570-3036d93beac7" />

# Text searching:

<img width="1250" height="726" alt="kyb4" src="https://github.com/user-attachments/assets/bcdafd3a-287d-4e70-9d2c-68fa06847a44" />
