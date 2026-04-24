# Batch Binary File Scanner
This is a standalone GUI Batch Binary File Scanner I made in Python and Dart (the executable is a dart script compiled) to make finding data/text significantly easier/quicker. Instead of you having to open thousands of files 1 by 1 in a hex editor (which would be time consuming) to search for 1 thing, you can use this. 

The tool will scan all files within a directory you select including subdirectories, it also tells you the file and the offsets of what you searched was found at. It accepts hex or text for searches. You can also select the character encoding to use for searching when using text searches. The current encodings I have supported are utf-8, shift-jis, and big-5. If you want support for more encodings, let me know. Shift-Jis is the most common character encoding for Japanese text in Japanese games and Big-5 for Chinese developed games, this will make finding Japanese/Chinese dialogue a lot easier if you originally had thousands of files you had to open manually, instead just type in what you want and have the scanner search for you.

I also included compression searching, the only algorithm I added support for is ZLIB which uses deflate. Compression searching means it will compress your text/bytes with ZLIB and search for the compressed version. If enough people are interested in compression searching, i'll add support for other compression algorithms.

Wildcard scanning is also supported, if you know part of the data to something but not all of it, you can use wildcards inplace of values you don't know. This scanner uses ?? as a wildcard, for any byte values you don't know you can use ?? to replace the value you're missing.

This tool can be used for any game/files. 

You need Python 3 installed to use this, keep the pyw file in the same directory as the exe file (aldnoah_scanner.exe).

# How it works

I am using python for the GUI while Dart does the bulk of the batch binary scanning. Essentially? By having a lot of the heavy work done by Dart, the scanning becomes significantly faster.

# Extra Info

The Dart_Source directory is just to provide the source to the Dart code, you don't actually use the .dart file, instead you use the pyw file and python will automatically call the executable version (which is the compiled version of thee dart source).

# Array of byte scan example
![h1](https://github.com/user-attachments/assets/0a4980fd-c217-4202-bc20-bddeda5cba09)

# Wildcard searching example:
![h2](https://github.com/user-attachments/assets/7eb449c8-9b0e-4d40-8e3c-836515fc88a6)

# Text searching:
![h3](https://github.com/user-attachments/assets/9894b91a-8cac-4b2b-9e37-1e689eb69057)

# Shift-Jis searching example:
![h4](https://github.com/user-attachments/assets/463d99ef-0d31-498c-afad-a1b38dfcbbb5)
