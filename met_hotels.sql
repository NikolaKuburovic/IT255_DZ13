-- phpMyAdmin SQL Dump
-- version 3.4.10.1deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Aug 31, 2016 at 01:47 PM
-- Server version: 5.5.50
-- PHP Version: 5.3.10-1ubuntu3.24

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `met_hotels`
--

-- --------------------------------------------------------

--
-- Table structure for table `hotel`
--

CREATE TABLE IF NOT EXISTS `hotel` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `naziv` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `brojSoba` int(11) NOT NULL,
  `kategorija` int(11) NOT NULL,
  `adresa` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `lokacija` varchar(30) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=10 ;

--
-- Dumping data for table `hotel`
--

INSERT INTO `hotel` (`id`, `naziv`, `brojSoba`, `kategorija`, `adresa`, `lokacija`) VALUES
(1, 'MetMount', 70, 3, 'Crni Vrh', 'Crni Vrh'),
(2, 'MetPark', 30, 4, 'Nova ulica 4', 'Vrnjacka Banja'),
(3, 'MetNature', 40, 5, 'Bulevar 70', 'Novi Sad'),
(4, 'MetLake', 25, 5, 'Srebrno Jezero bb', 'Srebrno Jezero'),
(6, 'MetOcean', 120, 4, 'Ocean View 150', 'New York'),
(8, 'MetHostel', 15, 3, 'Nova ulica 10', 'Zlatibor');

-- --------------------------------------------------------

--
-- Table structure for table `korisnik`
--

CREATE TABLE IF NOT EXISTS `korisnik` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ime` varchar(150) COLLATE utf8_unicode_ci NOT NULL,
  `prezime` varchar(150) COLLATE utf8_unicode_ci NOT NULL,
  `username` varchar(150) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(150) COLLATE utf8_unicode_ci NOT NULL,
  `token` varchar(128) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=20 ;

--
-- Dumping data for table `korisnik`
--

INSERT INTO `korisnik` (`id`, `ime`, `prezime`, `username`, `password`, `token`) VALUES
(1, 'Jovan', 'Jovanovic', 'jojov', 'e10adc3949ba59abbe56e057f20f883e', '3f10747bbb283318e3a299026e5a7df34df674fd'),
(2, 'Milan', 'Milanovic', 'mill', 'e10adc3949ba59abbe56e057f20f883e', 'f19342bccdbdc4674d81f8f032489fe2e431643d'),
(3, 'Jovana', 'Jovanovic', 'jovajo', 'e10adc3949ba59abbe56e057f20f883e', ''),
(4, 'Petar', 'Petrovic', 'petrov', 'e10adc3949ba59abbe56e057f20f883e', ''),
(5, 'Dusko', 'Duskovic', 'dusk', 'e10adc3949ba59abbe56e057f20f883e', ''),
(6, 'Vesna', 'Vesnic', 'vesve', 'e10adc3949ba59abbe56e057f20f883e', ''),
(7, 'Janko', 'Jankovic', 'janko', 'e10adc3949ba59abbe56e057f20f883e', ''),
(8, 'Milos', 'Milosevic', 'milosm', 'e10adc3949ba59abbe56e057f20f883e', ''),
(9, 'Stojan', 'Stojanovic', 'stojann', 'e10adc3949ba59abbe56e057f20f883e', ''),
(10, 'Stanko', 'Stankovic', 'stan', 'e10adc3949ba59abbe56e057f20f883e', ''),
(11, 'Ana', 'Anic', 'aanic', 'e10adc3949ba59abbe56e057f20f883e', '7983347551d32d66cfc9a66950716151e26bc513'),
(12, 'Djuro', 'Djuric', 'ddjur', 'e10adc3949ba59abbe56e057f20f883e', 'c565ac2c4a8b23e2f5c310d974967ae1882733f8'),
(13, 'Marija', 'Marijanovic', 'mmarr', 'e10adc3949ba59abbe56e057f20f883e', '1c702603a32e30fe0b9c19ebacc3008a7d465cf0'),
(14, 'Srecko', 'Sreckovic', 'sreckos', 'e10adc3949ba59abbe56e057f20f883e', 'fe15e5407c31d729f113429e2e9342258e657c8a'),
(15, 'Pavle', 'Pavlovic', 'pavlep', 'e10adc3949ba59abbe56e057f20f883e', '123a9e7b0f5c4acca3191f7714067b9e4253d08f'),
(16, 'Milena', 'Milenovic', 'milenam', 'e10adc3949ba59abbe56e057f20f883e', '34d918fb008ec8839e83bdd0ab044e39f896e1ae'),
(17, 'Zarko', 'Zarkovic', 'zzarr', 'e10adc3949ba59abbe56e057f20f883e', 'c96bffc62a813a2bf21f7c1a56328c43bf075332'),
(18, 'Mihailo', 'Mihailovic', 'mihail', 'e10adc3949ba59abbe56e057f20f883e', '1be32e81eca57272df2218cccfbc200ab2829334');

-- --------------------------------------------------------

--
-- Table structure for table `soba`
--

CREATE TABLE IF NOT EXISTS `soba` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ime` varchar(30) COLLATE utf8_unicode_ci NOT NULL,
  `sprat` int(11) NOT NULL,
  `kreveti` int(11) NOT NULL,
  `m2` int(11) NOT NULL,
  `tv` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `internet` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `djakuzi` varchar(10) COLLATE utf8_unicode_ci NOT NULL,
  `rezervacija` varchar(15) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ime_sobe` (`ime`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=374 ;

--
-- Dumping data for table `soba`
--

INSERT INTO `soba` (`id`, `ime`, `sprat`, `kreveti`, `m2`, `tv`, `internet`, `djakuzi`, `rezervacija`) VALUES
(102, 'Ubedljivo Najbolji Apartman', 5, 3, 20, 'Da', 'Da', 'Ne', 'REZERVISANA'),
(202, 'Novi Apartman', 2, 2, 22, 'Da', 'Da', 'Da', 'REZERVISANA'),
(239, 'Huge Apartman', 5, 3, 25, 'Da', 'Da', 'Da', 'REZERVISANA'),
(301, 'Gornji Apartman', 3, 4, 32, 'Da', 'Da', 'Da', 'SLOBODNA'),
(303, 'Najbolji Apartman', 3, 3, 25, 'Da', 'Da', 'Da', 'SLOBODNA'),
(304, 'Najtrazeniji apartman', 4, 2, 20, 'Da', 'Da', 'Da', 'SLOBODNA'),
(305, 'Najlepsi Apartman', 5, 2, 30, 'Da', 'Da', 'Da', 'SLOBODNA'),
(306, 'Extra Apartman', 5, 4, 22, 'Da', 'Da', 'Da', 'REZERVISANA'),
(307, 'Veliki Apartman', 4, 4, 30, 'Da', 'Da', 'Da', 'REZERVISANA'),
(308, 'Top Apartman', 5, 2, 25, 'Da', 'Da', 'Da', 'SLOBODNA'),
(314, 'Deluxe Apartman', 6, 2, 30, 'Da', 'Da', 'Ne', 'SLOBODNA'),
(315, 'Super Apartman', 5, 4, 35, 'Da', 'Da', 'Da', 'SLOBODNA'),
(319, 'Best Apartman', 3, 3, 20, 'Da', 'Ne', 'Ne', 'SLOBODNA'),
(320, 'Exclusive Apartman', 5, 1, 30, 'Da', 'Ne', 'Ne', 'SLOBODNA'),
(321, 'Fine Apartman', 5, 1, 20, 'Da', 'Ne', 'Ne', 'SLOBODNA'),
(322, 'Beautiful Apartman', 4, 2, 25, 'Da', 'Da', 'Da', 'SLOBODNA'),
(323, 'Etno Apartman', 5, 3, 30, 'Da', 'Ne', 'Ne', 'SLOBODNA'),
(325, 'The Best Apartman', 5, 2, 28, 'Da', 'Da', 'Ne', 'REZERVISANA'),
(327, 'Najnoviji Apartman', 5, 2, 20, 'Da', 'Da', 'Ne', 'REZERVISANA'),
(328, 'Prvi Apartman', 6, 4, 30, 'Da', 'Da', 'Ne', 'SLOBODNA'),
(330, 'Wide Apartman', 4, 4, 35, 'Da', 'Da', 'Ne', 'REZERVISANA'),
(331, 'Bold Apartman', 3, 4, 32, 'Ne', 'Ne', 'Ne', 'SLOBODNA'),
(332, 'Greatest Apartman', 3, 2, 20, 'Da', 'Da', 'Da', 'SLOBODNA'),
(333, 'Nature Apartman', 4, 3, 27, 'Da', 'Da', 'Ne', 'REZERVISANA'),
(334, 'Najmanji Apartmen', 2, 1, 12, 'Da', 'Da', 'Ne', 'SLOBODNA'),
(335, 'Renovirani Apartman', 2, 2, 25, 'Da', 'Da', 'Da', 'SLOBODNA'),
(337, 'Suncani Apartman', 3, 2, 25, 'Da', 'Da', 'Da', 'SLOBODNA'),
(340, 'Obicni Apartman', 5, 2, 28, 'Da', 'Da', 'Ne', 'SLOBODNA'),
(371, 'Eco Apartman', 3, 3, 28, 'Da', 'Da', 'Ne', 'SLOBODNA'),
(372, 'Classic Apartman', 2, 3, 34, 'Da', 'Da', 'Ne', 'SLOBODNA');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
