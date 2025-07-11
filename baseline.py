import gdb

class BaselineTimer(gdb.Command):
    """
    GDB script to run the program without any defense.
    This command simply runs the program without stepping through instructions.
    """

    def __init__(self):
        super(BaselineTimer, self).__init__("baseline", gdb.COMMAND_USER)
        print("✅ baseline_timer.py loaded. Command 'baseline' is registered.")

    def invoke(self, arg, from_tty):
        """
        GDB entry point for the 'baseline' command.
        Starts from _start and runs the program until completion.
        """
        # Run the program
        gdb.execute("run")

        # Once the program finishes, quit GDB
        print("[INFO] Program execution finished.")
        gdb.execute("quit")

# Register the custom GDB command
BaselineTimer()