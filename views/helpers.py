from views.style import highlight


def print_header(title: str, header_length: int = 70):
    title_length = len(title) + 2
    leftover_space = header_length - title_length
    even_padding = leftover_space % 2 == 0
    padding_length = leftover_space // 2

    padding_str = ("=" * padding_length)

    if even_padding:
        print(f"\n{padding_str} {title} {padding_str}\n")
    else:
        print(f"\n{padding_str} {title} {padding_str + "="}\n")
