class FastMCP:
    def __init__(self, name: str):
        self.name = name
        self.tools = {}
        self.prompts = {}
        self.resources = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func
        return decorator

    def prompt(self, name: str):
        def decorator(func):
            self.prompts[name] = func
            return func
        return decorator

    def resource(self, name: str):
        def decorator(func):
            self.resources[name] = func
            return func
        return decorator