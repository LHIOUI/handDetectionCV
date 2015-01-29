CC=g++
CXXFLAGS=-g -DDEBUG -DDEBUG_WINDOW -std=c++11

manusa: main.o myImage.o handGesture.o roi.o
	$(CC) $^ -o $@ $(CXXFLAGS) `pkg-config --cflags --libs opencv`

main.o: main.cpp

myImage.o: myImage.cpp

handGesture.o: handGesture.cpp

roi.o: roi.cpp

all:
	g++ -o manusa main.cpp myImage.cpp handGesture.cpp roi.cpp `pkg-config --cflags --libs opencv` -DDEBUG -lssh

clean:
	rm -f *~ *.o manusa

