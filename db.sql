--
-- PostgreSQL database dump
--

-- Dumped from database version 15.1 (Ubuntu 15.1-1.pgdg20.04+1)
-- Dumped by pg_dump version 15.1 (Ubuntu 15.1-1.pgdg20.04+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: groupmembers; Type: TABLE; Schema: public; Owner: fasty
--

CREATE TABLE public.groupmembers (
    groupname text NOT NULL,
    key text NOT NULL,
    username text NOT NULL
);


ALTER TABLE public.groupmembers OWNER TO fasty;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: fasty
--

CREATE TABLE public.groups (
    groupname text NOT NULL,
    creator text NOT NULL,
    creatorkey text NOT NULL
);


ALTER TABLE public.groups OWNER TO fasty;

--
-- Name: messages; Type: TABLE; Schema: public; Owner: fasty
--

CREATE TABLE public.messages (
    sender text NOT NULL,
    receiver text NOT NULL,
    message text NOT NULL,
    "timestamp" double precision NOT NULL,
    contenttype text NOT NULL
);


ALTER TABLE public.messages OWNER TO fasty;

--
-- Name: users; Type: TABLE; Schema: public; Owner: fasty
--

CREATE TABLE public.users (
    name text NOT NULL,
    password text NOT NULL,
    e2epublickey text NOT NULL
);


ALTER TABLE public.users OWNER TO fasty;

--
-- Name: users users_name_key; Type: CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_name_key UNIQUE (name);


--
-- PostgreSQL database dump complete
--

