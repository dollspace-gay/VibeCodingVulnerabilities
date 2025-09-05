# ChatGPT code snippets

This repository contains code only generated using GPT-5 via the OpenAI API. These code snippets were written for [an XDA article](https://www.xda-developers.com/tried-vibe-coding-chatgpt-vulnerabilities/) to demonstrate the vulnerabilities associated with "vibe coding", and how AI-generated code requires hardening and external review before deployment in a production environment. This code is output straight from ChatGPT without any changes, aside from repairing the syntax associated with the generated HTML in the C web server.

## MQTT stats

This program is written in C++, and reports current system statistics to an MQTT broker.

There is no authorization, there is no validation in regards to reporting intervals, and the --topic flag is user controlled. If MQTT persistence is also enabled, then path traversal would allow for an attacker to write to any folder the broker has write access to.

## List folder

This program is written in Python, and lists the files in a given folder. 

On Linux, macOS, and BSD, additional flags can be inserted at the start of an input to modify the listing behavior. On Windows, it allows for full command injection.

## CSV file reader

This program is written in C, and parses and prints a given CSV.

It defines a hard-coded character limit of 1024, and a line of 1023 characters will force the current row to continue on the next line once it hits this limit. As well, the use of the strtok function will not handle empty fields correctly and will fail to handle quotes. Finally, it is also vulnerable to path traversal.

## C web server

This program is written in C, and hosts a web server that a user can upload a file to. It contained syntax errors in relation to the HTML code generated, and I've cleaned it for this demonstration. No other code was modified.

The header and the body are unbounded, it's single-threaded and will block for a long upload, and files are stored with 0755 permissions. This means uploaded files can be read globally on the system. The ```hdrs[hdr_len] = '\0';``` line is indicative of the biggest danger in this code:

When ```parse_headers``` is called, the local hdrs value references a buffer created in ```handle_connection```. This buffer is defined by ```char * buf = (char * ) malloc(cap + 1);```, where it creates a buffer of the maximum length plus one. Using ```hdrs[hdr_len] = '\0';``` sets this final byte to a null terminator, but someone who modifies or adjusts this program may not be aware of the implications of this and could inadvertently allow for a buffer overflow attack should the byte not be added later on.