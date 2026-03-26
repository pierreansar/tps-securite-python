from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {str(i): f"http://{ip}/captcha{i}/" for i in range(1, 4)}

    for i in challenges:
        url = challenges[i]
        session = Session(url)
        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
