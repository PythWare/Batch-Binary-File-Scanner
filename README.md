# Batch-Binary-File-Scanner
This is a standalone Batch Binary File Scanner I made in Python to make finding data/text significantly easier/quicker. Instead of you having to open thousands of files 1 by 1 in a hex editor (which would be time consuming) to search for 1 thing, you can use this. 

The tool will scan all files within a directory you select including subdirectories. It accepts hex or text for searches. You can also select the character encoding to use for searching when using text searches. The current encodings I have supported are utf-8, shift-jis, and big-5. If you want support for more encodings, let me know. Shift-Jis is the most common character encoding for Japanese text in Japanese games, Big-5 for Chinese developed games. 

I also included compression searching, the only algorithm I added support for is ZLIB which uses deflate. Compression searching means it will compress your text/bytes with ZLIB and search for the compressed version. If enough people are interested in compression searching, i'll add support for other compression algorithms.

Wildcard scanning is also supported, if you know part of the data to something but not all of it, you can use wildcards inplace of values you don't know. This scanner uses ?? as a wildcard, for any byte values you don't know you can use ?? to replace the value you're missing.

This tool can be used for any game/files. 

You need Python 3 installed to use this. 
