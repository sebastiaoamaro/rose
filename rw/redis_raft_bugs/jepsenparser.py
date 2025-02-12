import argparse

def find_lines_with_words(file_path, words):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            
        matching_lines = [line for line in lines if all(word in line for word in words)]
        
        if matching_lines:
            print("Lines containing the words 'nemesis' and 'pause':")
            for line in matching_lines:
                print(line.strip())
        else:
            print("No lines found containing the words 'nemesis' and 'pause'.")
    
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find lines containing specific words in a text file.")
    parser.add_argument('file_path', type=str, help="Path to the text file")
    parser.add_argument('words', type=str, nargs='+', help="Words to search for in the file")
    
    args = parser.parse_args()
    find_lines_with_words(args.file_path, args.words)