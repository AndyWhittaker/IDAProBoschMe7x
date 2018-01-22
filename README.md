# BoschMe7x
IDA Pro Bosch ME7x C16x Disassembler Helper

This is a very simple plugin for IDA Pro mainly to save a few hours of work. This is also my very first GitHub project and I don't know what I'm doing yet!

This IDA Pro plug-in reads in a Bosch ME7.x binary, asks a few questions and then goes through said binary, trying to disassemble it.

## Important Points

Because a binary is essentially a collection of bytes, there is no formatting of an executable like you would expect on, say, a Windows exe or a Linux executable. Therefore you have to instruct IDA to load the binary exactly as it should be.

Tell IDA that:
The processor is a Siemens C166 family [c166]
Create a RAM section with the start address at 0x0e0000 with a size of 0x0400
Create a ROM section with a start address at 0x800000, the ROM size should be automatic.
In the Input File section set the loading address to 0x800000

Click OK and when asked, select the device names to be C167CR_SR

The binary is now loaded correctly. Assuming the .plw file is in the plugins directory, click on Edit.Plugins->BoschME7x and away we go.

## Built With

This project is written in bad C++ within Microsoft's Visual Studio 2017 community edition.

## Contributing

Please contribute all that you can; I'm not an IDA Pro professional but would like some help digging through the documentation.

## Authors

* **Andy Whittaker** - *Initial work*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
