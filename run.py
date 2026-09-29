from sentinelle import create_app

app = create_app()

if __name__ == "__main__":
    # debug=True uniquement en développement local
    app.run(host="127.0.0.1", port=5000, debug=True)
