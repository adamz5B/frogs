-- get_car_by_maker_model.sql
SELECT vin, maker, model, year, trim, listed_at
FROM cars
WHERE maker = :maker AND model = :model
LIMIT 1;