#!/usr/bin/python3

def main():
    data = []
    while True:
        line = input()
        if line[0] == '}':
            break
        data.append(line)

    data = data[1:]
    for line in data:
        print(f'"{line[:-1].strip()}", ')


if __name__ == '__main__':
    main()
