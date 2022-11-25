--
-- PostgreSQL database dump
--

-- Dumped from database version 14.6 (Homebrew)
-- Dumped by pg_dump version 14.6 (Homebrew)

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
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (groupname);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (name);


--
-- Name: groupmembers groupmembers_groupname_fkey; Type: FK CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.groupmembers
    ADD CONSTRAINT groupmembers_groupname_fkey FOREIGN KEY (groupname) REFERENCES public.groups(groupname);


--
-- Name: groupmembers groupmembers_username_fkey; Type: FK CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.groupmembers
    ADD CONSTRAINT groupmembers_username_fkey FOREIGN KEY (username) REFERENCES public.users(name);


--
-- Name: groups groups_creator_fkey; Type: FK CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_creator_fkey FOREIGN KEY (creator) REFERENCES public.users(name);


--
-- Name: messages messages_receiver_fkey; Type: FK CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_receiver_fkey FOREIGN KEY (receiver) REFERENCES public.users(name);


--
-- Name: messages messages_sender_fkey; Type: FK CONSTRAINT; Schema: public; Owner: fasty
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_fkey FOREIGN KEY (sender) REFERENCES public.users(name);


--
-- PostgreSQL database dump complete
--

