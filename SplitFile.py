# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


# Press the green button in the gutter to run the script.

import os, tempfile

if __name__ == '__main__':

    my_file = r'C:\temp\Pemex\Dedupe.txt'
    sorting = True
    hold_lines = []
    with open(my_file,'r') as text_file:
        for row in text_file:
            hold_lines.append(row)
    outer_count = 1
    line_count = 0
    while sorting:
        count = 0
        increment = (outer_count-1) * 100
        left = len(hold_lines) - increment
        file_name = "small_file_" + str(outer_count * 100) + ".txt"
        hold_new_lines = []
        if left < 100:
            while count < left:
                hold_new_lines.append(hold_lines[line_count])
                count += 1
                line_count += 1
            sorting = False
        else:
            while count < 100:
                hold_new_lines.append(hold_lines[line_count])
                count += 1
                line_count += 1
            outer_count += 1
            with open(file_name,'w') as next_file:
                for row in hold_new_lines:
                    next_file.write(row)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
