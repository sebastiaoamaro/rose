import sys
def check_lost_elements(file_path):
    """
    Reads a file containing lists and checks for lost elements between consecutive lists.
    """
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        previous_list = None

        for line in lines:
            try:
                current_list = eval(line.split('|')[2])

                if previous_list is not None:
                    lost_elements = set(previous_list) - set(current_list)
                    if lost_elements:
                        print(f"Lost elements: {lost_elements}")
                        break
                previous_list = current_list

            except (IndexError, SyntaxError):
                print(f"Skipping invalid line: {line.strip()}")

    except FileNotFoundError:
        print(f"File not found: {file_path}")


def main():
    """
    Main function to execute the script.
    """
    file_path = sys.argv[1]  # Replace with your file path
    check_lost_elements(file_path)


if __name__ == "__main__":
    main()
