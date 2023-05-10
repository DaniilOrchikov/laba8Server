package utility;
import ticket.Ticket;
import ticket.TicketType;
import ticket.Venue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Класс, отвечающий за организацию хранения и доступа к объектам класса {@link Ticket}. Тип коллекции, в которой хранятся объекты - Vector
 */
public class TicketVector {
    private final AtomicLong id = new AtomicLong(0);
    /**
     * Поле даты и времени создания данного объекта
     */
    private final java.time.ZonedDateTime creationDate;
    /**
     * Поле коллекции, в которой хранятся объекты класса {@link Ticket}
     */
    private Vector<Ticket> tv = new Vector<>();
    /**
     * Поле длинны коллекции tv
     *
     * @see TicketVector#tv
     */
    private final AtomicLong length = new AtomicLong(0);

    public TicketVector() {
        creationDate = java.time.ZonedDateTime.now();
    }

    /**
     * Добавляет объект в коллекцию. При этом, если id объекта неоригинально, он не будет добавлен
     *
     * @param ticket объект класса {@link  Ticket}
     */
    public synchronized void add(Ticket ticket) {
        tv.add(ticket);
        length.incrementAndGet();
        id.incrementAndGet();
    }

    public synchronized void clear() {
        tv.clear();
        length.set(0);
        id.incrementAndGet();
    }

    /**
     * Обновляет элемент коллекции с указанным id
     *
     * @param ticket объект типа {@link Ticket}
     * @param id     id объекта, который надо обновить. Предполагается, что id проверенно на корректность (в коллекции существует элемент с таким id) {@link TicketVector#validId}
     */
    public synchronized void update(Ticket ticket, long id) {
        tv.removeIf(t -> t.getId() == id);
        length.decrementAndGet();
        this.id.incrementAndGet();
        add(ticket);
    }


    /**
     * Удаляет элемент по переданному индексу
     *
     * @param index индекс элемента, который нужно удалить
     */
    public synchronized void remove(int index) {
        tv.remove(index);
        length.decrementAndGet();
        id.incrementAndGet();
    }

    /**
     * Удаляет все элементы коллекции, меньшие переданного объекта
     *
     * @param ticket объект класса {@link Ticket}, с которым производится сравнение {@link Ticket#compareTo}
     * @return возвращает количество удаленных объектов
     */
    public synchronized int removeLower(Ticket ticket) {
        List<Ticket> delTickets = tv.stream().filter(t -> ticket.compareTo(t) > 0 && t.getUserName().equals(ticket.getUserName())).toList();
        length.addAndGet(-delTickets.size());
        tv.removeAll(delTickets);
        this.id.incrementAndGet();
        return delTickets.size();
    }

    /**
     * @return возвращает массив со всеми элементами коллекции
     */
    public synchronized Ticket[] getAll() {
        return sortBySize(tv.stream().toList()).toArray(new Ticket[0]);
    }

    /**
     * Удаляет элемент коллекции с указанным id
     *
     * @param id id элемента, который нужно удалить. Предполагается, что id проверенно на корректность (в коллекции существует элемент с таким id) {@link TicketVector#validId}
     */
    public synchronized void removeById(long id) {
        length.addAndGet(-tv.size());
        tv.removeIf(t -> t.getId() == id);
        length.addAndGet(tv.size());
        this.id.incrementAndGet();
    }

    /**
     * @return возвращает минимальный элемент коллекции в строковом представлении. Сравнение ведется по полю venue {@link Venue#compareTo}
     */
    public synchronized String getMinByVenue() {
        Optional<Ticket> t = tv.stream().min(Comparator.comparing(Ticket::getVenue));
        return t.isPresent() ? t.get().toString() : "Массив пустой";
    }

    /**
     * @param str строка, по которой ведется поиск
     * @return возвращает элементы, значение поля name которых содержит заданную подстроку
     */
    public synchronized List<Ticket> filterContainsName(String str) {
        return sortBySize(tv.stream().filter(t -> t.getName().contains(str)).toList());
    }

    /**
     * @param price число
     * @return возвращает элементы, значение поля price которых меньше заданного
     */
    public synchronized List<Ticket> filterLessThanPrice(int price) {
        return sortBySize(tv.stream().filter(t -> t.getPrice() < price).toList());
    }

    /**
     * @param price число
     * @return возвращает элементы, значение поля price которых равно заданному
     */
    public synchronized List<Ticket> filterByPrice(int price) {
        return sortBySize(tv.stream().filter(t -> t.getPrice() == price).toList());
    }

    /**
     * @return возвращает значения поля type всех элементов в порядке возрастания {@link TicketType}
     */
    public synchronized String getFieldAscendingType() {
        StringBuilder str = new StringBuilder();
        tv.stream().sorted((t1, t2) -> t2.getType().compareTo(t1.getType())).forEach(t -> str.append(String.format("id:%s - type:%s\n", t.getId(), t.getType())));
        return str.toString();
    }

    /**
     * @param type тип билета {@link TicketType}
     * @return возвращает количество элементов коллекции, тип которых превышает переданный
     */
    public synchronized long getCountGreaterThanType(TicketType type) {
        return tv.stream().filter(t -> type.compareTo(t.getType()) > 0).count();
    }

    /**
     * @return возвращает максимальный элемент коллекции {@link Ticket#compareTo}.
     * Если коллекция пуста вернет null
     */
    public synchronized Ticket maxTicket() {
        return tv.stream().max(Ticket::compareTo).orElse(null);
    }

    /**
     * @return возвращает минимальный элемент коллекции {@link Ticket#compareTo}.
     * Если коллекция пуста вернет null
     */
    public synchronized Ticket minTicket() {
        return tv.stream().min(Ticket::compareTo).orElse(null);
    }

    /**
     * @return возвращает информацию об коллекции <b>дата инициализации {@link TicketVector#creationDate}</b>, <b>количество элементов {@link TicketVector#length}</b>, <b>максимальный элемент {@link TicketVector#maxTicket}</b>, <b>минимальный элемент {@link TicketVector#minTicket}</b>
     */
    public synchronized String getInfo() {
        return String.format("Тип - Vector\nДата инициализации - %s\nКоличество элементов - %s\nМаксимальный элемент - %s\nМинимальный элемент - %s", creationDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss ZZ")), length, maxTicket(), minTicket());
    }

    /**
     * Проверяет, что элемент с указанным id есть в коллекции
     *
     * @param id число
     * @return возвращает true, если в коллекции есть элемент с указанным id, false - если нет
     */
    public synchronized boolean validId(long id) {
        return tv.stream().anyMatch(t -> t.getId() == id);
    }

    /**
     * Сортирует передаваемую коллекцию по возрастанию размера объекта
     *
     * @param arr передаваемая коллекция
     * @return возвращает отсортированную последовательность
     */

    public List<Ticket> sortBySize(List<Ticket> arr) {
        return arr.stream().sorted((t1, t2) -> {
            int s1, s2;
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos);
                oos.writeObject(t1);
                s1 = baos.size();
                oos = new ObjectOutputStream(baos);
                oos.writeObject(t2);
                oos.close();
                s2 = baos.size() - s1;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return Long.compare(s1, s2);
        }).toList();
    }

    public Long getIdByIndex(int index) {
        if (index >= length.get()) return -1L;
        return tv.get(index).getId();
    }
    public Ticket get(Long id){
        return tv.stream().filter(t-> Objects.equals(t.getId(), id)).toList().get(0);
    }
    public Long getId() {
        return id.longValue();
    }

    public String getCreationDate() {
        return creationDate.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss ZZ"));
    }
    public synchronized void clearByUser(String userName){
        tv = tv.stream().filter(t->!t.getUserName().equals(userName)).collect(Collectors.toCollection(Vector::new));
        length.set(tv.size());
        id.incrementAndGet();
    }
}
