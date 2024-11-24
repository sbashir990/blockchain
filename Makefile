all:
	cp blockchain.py bchoc
	chmod +x bchoc

clean:
	rm -f bchoc blockchain.dat
