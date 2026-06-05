from app.cli import parse_args, resolve_analysis_flags
from app.controller import run


def main():
    params = parse_args()
    url = params.url

    # Early return if URL wasn't provided
    if not url:
        return
    
    params = resolve_analysis_flags(params)
    run(params)


if __name__ == "__main__":
    main()
