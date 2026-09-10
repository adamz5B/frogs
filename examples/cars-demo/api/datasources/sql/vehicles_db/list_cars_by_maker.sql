-- list_cars_by_maker.sql
SELECT vin, maker, model, year, trim, listed_at
FROM cars
WHERE maker = :maker
ORDER BY model;
