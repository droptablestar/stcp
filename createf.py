import sys

def main():
    written = 0
    f = open(sys.argv[2],'w')
    while written < int(sys.argv[1]):
        if (written+1) % 70 == 0:
            f.write('\n')
        else:
            f.write('a')
        written += 1

if __name__ == '__main__':
    main()
