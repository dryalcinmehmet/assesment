.PHONY : info
info :
	@echo "msg : Assesment Test"



.PHONY : dev
dev:  ## Build web
	@echo "[-----------------------------------------]"
	@echo "web building...."
	docker-compose up --build -d

.PHONY : prod
prod:  ## Build web
	@echo "[-----------------------------------------]"
	@echo "web building...."
	docker-compose -f docker-compose.prod.yml up --build -d

.PHONY : devdown
devdown:  ## Build web
	@echo "[-----------------------------------------]"
	@echo "web building...."
	docker-compose down -v

.PHONY : proddown
proddown:  ## Build web
	@echo "[-----------------------------------------]"
	@echo "web building...."
	docker-compose -f docker-compose.prod.yml down -v

