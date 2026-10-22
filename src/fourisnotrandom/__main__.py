from fourisnotrandom.cli import app

if __name__ == "__main__":
    # Disable Click's Windows argv glob expansion so a literal "*" is rejected
    # by TargetError instead of being expanded into a directory sweep.
    app(windows_expand_args=False)
